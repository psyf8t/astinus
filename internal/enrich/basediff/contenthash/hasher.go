package contenthash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
)

// HashStream computes the SHA-256 of r as the stream is consumed,
// returning the lowercase hex digest and the number of bytes hashed.
//
// Memory is constant (one SHA-256 state, ~200 bytes) regardless of
// input size — io.Copy uses a small buffer behind the scenes, so a
// 100 MiB blob hashes in O(1) memory.
func HashStream(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// HashCache memoises (path, size) → hash inside a single scan. The
// (path, size) key catches the common case where the same file is
// emitted under different effective paths (hardlinks, copies) and
// avoids re-hashing identical bytes.
//
// Safe for concurrent use. The cache is intentionally per-scan —
// don't share across enrichers; the path identity (Layer.Index +
// canonical path) is only meaningful within one image walk.
type HashCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

// NewHashCache returns an empty cache.
func NewHashCache() *HashCache {
	return &HashCache{cache: map[string]string{}}
}

// Key formats the cache lookup key from path + size. Exposed so the
// caller can compute the key once and pass it to both Get and Set
// without re-formatting.
func (c *HashCache) Key(path string, size int64) string {
	return path + "\x00" + itoa(size)
}

// Get returns the cached hash for key plus a hit indicator.
func (c *HashCache) Get(key string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.cache[key]
	return v, ok
}

// Set stores hash under key.
func (c *HashCache) Set(key, hash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = hash
}

// Size reports the number of entries.
func (c *HashCache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// itoa is the same as strconv.FormatInt(n, 10) but inlined to keep
// the hot path free of imports the rest of the file does not need.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
