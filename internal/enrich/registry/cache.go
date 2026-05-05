package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache is the registry-metadata memo. Implementations:
//
//   - MemoryCache (always on; per-process)
//   - DiskCache (opt-in via --registry-cache-dir; survives restarts)
//   - Layered (memory in front of disk; default in production)
//
// The cache stores Metadata keyed by the canonical PURL string. A
// hit with a nil Metadata means "we asked, nobody had anything" —
// the resolver should not re-walk the source chain.
type Cache interface {
	Get(purl string) (*Metadata, bool)
	Set(purl string, meta *Metadata)
}

// NoopCache disables caching entirely. Used by tests that want to
// exercise per-Source behaviour deterministically.
type NoopCache struct{}

// Get implements Cache.
func (NoopCache) Get(string) (*Metadata, bool) { return nil, false }

// Set implements Cache.
func (NoopCache) Set(string, *Metadata) {}

// MemoryCache is the in-process LRU-shaped (actually plain map)
// memo. Concurrency-safe.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*Metadata
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: map[string]*Metadata{}}
}

// Get implements Cache.
func (c *MemoryCache) Get(purl string) (*Metadata, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.entries[purl]
	return m, ok
}

// Set implements Cache.
func (c *MemoryCache) Set(purl string, m *Metadata) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[purl] = m
}

// Size reports the entry count. Useful for log lines + tests.
func (c *MemoryCache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// DiskCache stores Metadata as JSON files under a root directory.
// Each entry's path is `<root>/<sha256(purl)[:2]>/<sha256(purl)>.json`.
// Sharded by the first byte to keep directory size bounded on
// catalogues > 100k entries.
//
// TTL is enforced on Get: an entry whose mtime is older than ttl is
// deleted and treated as a miss. Zero TTL disables expiry (kept
// indefinitely).
type DiskCache struct {
	root string
	ttl  time.Duration
}

// NewDiskCache returns a DiskCache rooted at root. Creates the
// directory if missing. ttl=0 disables expiry. The first
// out-of-band caller to write to root wins; concurrent processes
// see the disk file but in-process consistency is the caller's
// concern (today the enricher serialises calls per-PURL via the
// memory layer).
func NewDiskCache(root string, ttl time.Duration) (*DiskCache, error) {
	if root == "" {
		return nil, errors.New("registry: disk cache root is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &DiskCache{root: root, ttl: ttl}, nil
}

// Get implements Cache. Returns (nil, false) on miss, on parse
// failure, or when the entry is older than ttl.
func (c *DiskCache) Get(purl string) (*Metadata, bool) {
	if c == nil {
		return nil, false
	}
	path := c.pathFor(purl)
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if c.ttl > 0 && time.Since(info.ModTime()) > c.ttl {
		_ = os.Remove(path)
		return nil, false
	}
	body, err := os.ReadFile(path) //nolint:gosec // path is sha-derived under root
	if err != nil {
		return nil, false
	}
	var meta Metadata
	if err := json.Unmarshal(body, &meta); err != nil {
		// Corrupt entry — drop it so the next call re-fetches.
		_ = os.Remove(path)
		return nil, false
	}
	return &meta, true
}

// Set implements Cache. Best-effort write — failures are logged at
// the caller (the cache layer doesn't take a logger to avoid
// coupling it to slog).
func (c *DiskCache) Set(purl string, meta *Metadata) {
	if c == nil || meta == nil {
		return
	}
	path := c.pathFor(purl)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil { //nolint:gosec // 644 is right for a cache
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// pathFor computes the on-disk path for purl.
func (c *DiskCache) pathFor(purl string) string {
	sum := sha256.Sum256([]byte(purl))
	hexSum := hex.EncodeToString(sum[:])
	return filepath.Join(c.root, hexSum[:2], hexSum+".json")
}

// LayeredCache is a memory cache fronting a disk cache. Reads check
// memory first (zero-cost), then disk; writes update both. Returned
// by the resolver constructor when --registry-cache-dir is set.
type LayeredCache struct {
	mem  *MemoryCache
	disk *DiskCache
}

// NewLayeredCache returns a memory-front, disk-back cache.
func NewLayeredCache(mem *MemoryCache, disk *DiskCache) *LayeredCache {
	if mem == nil {
		mem = NewMemoryCache()
	}
	return &LayeredCache{mem: mem, disk: disk}
}

// Get implements Cache.
func (c *LayeredCache) Get(purl string) (*Metadata, bool) {
	if c == nil {
		return nil, false
	}
	if m, ok := c.mem.Get(purl); ok {
		return m, true
	}
	if c.disk != nil {
		if m, ok := c.disk.Get(purl); ok {
			c.mem.Set(purl, m)
			return m, true
		}
	}
	return nil, false
}

// Set implements Cache.
func (c *LayeredCache) Set(purl string, meta *Metadata) {
	if c == nil {
		return
	}
	c.mem.Set(purl, meta)
	if c.disk != nil {
		c.disk.Set(purl, meta)
	}
}

// PurgeExpired (deferred): a `astinus registry-cache prune` CLI
// helper would walk the disk cache and remove stale entries. The
// fetch path already drops expired entries on read; standalone
// pruning is reserved for ADR-0033 §6 follow-ups.
