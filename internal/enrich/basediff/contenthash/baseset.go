package contenthash

import "sync"

// Evidence is the forensic record kept for one base-image file:
// where it lived (path + layer index) and how big it was. Stored on
// the BaseSet keyed by SHA-256 so a target lookup can recover the
// matching base path.
type Evidence struct {
	// BasePath is the file's path in the BASE image (canonical form
	// — slash-separated, no leading slash, matching layer.FileMap).
	BasePath string

	// LayerIndex is the 0-based index of the base layer that owns
	// the file (latest-layer-wins).
	LayerIndex int

	// Size is the file's uncompressed byte length.
	Size int64
}

// BaseSet indexes a base image's files by SHA-256.
//
// Lookups are cheap negative-case: the bloom filter rejects unknown
// hashes in O(k) bit checks before touching the exact map. Positive
// case is one map lookup. Concurrent reads after construction are
// safe; concurrent writes (Add) are guarded by an internal mutex
// since BuildBaseSet may parallelise hashing in the future.
//
// The set deliberately keeps only the FIRST evidence record per
// hash — duplicates within the base image (e.g. the same file
// hard-linked or copied to two paths) are common enough that
// keeping all of them would inflate memory without changing the
// match decision.
type BaseSet struct {
	mu        sync.RWMutex
	bloom     *bloom
	exact     map[string]Evidence
	basePaths map[string]struct{} // every path indexed (for "path exists in base?" checks)
}

// NewBaseSet returns a BaseSet sized for the expected number of
// distinct base files. The bloom filter targets a 1 % false-positive
// rate at that capacity; exceeding it gracefully degrades the rate
// rather than failing the lookup (the exact map is still
// authoritative).
func NewBaseSet(expectedFiles int) *BaseSet {
	if expectedFiles < 1 {
		expectedFiles = 1
	}
	return &BaseSet{
		bloom:     newBloom(expectedFiles, 0.01),
		exact:     make(map[string]Evidence, expectedFiles),
		basePaths: make(map[string]struct{}, expectedFiles),
	}
}

// Add records the hash → ev mapping. Calling Add with a hash that's
// already present preserves the first evidence (deterministic order
// up to the caller).
//
// Add also stamps ev.BasePath into the path-existence index so
// HasPath answers "does the base have a file at this path?" without
// a second walk.
func (b *BaseSet) Add(sha256Hex string, ev Evidence) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bloom.add(sha256Hex)
	if _, exists := b.exact[sha256Hex]; !exists {
		b.exact[sha256Hex] = ev
	}
	if ev.BasePath != "" {
		b.basePaths[ev.BasePath] = struct{}{}
	}
}

// Contains reports whether sha256Hex is in the base. Returns the
// stored Evidence on a hit, zero Evidence on a miss.
//
// Negative-case fast path: the bloom filter rejects ~99 % of
// non-members without touching the exact map. Positive case still
// pays the map lookup; the exact map is the source of truth (bloom
// false-positives would otherwise leak).
func (b *BaseSet) Contains(sha256Hex string) (Evidence, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.bloom.test(sha256Hex) {
		return Evidence{}, false
	}
	ev, ok := b.exact[sha256Hex]
	return ev, ok
}

// HasPath reports whether the base image carries a file at p
// (canonical form). Used by the caller to distinguish "modified at
// the same path" from "brand-new path" when the content hash didn't
// match.
func (b *BaseSet) HasPath(p string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.basePaths[p]
	return ok
}

// Size returns the number of distinct hashes recorded.
func (b *BaseSet) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact)
}

// PathCount returns the number of distinct base paths indexed.
// Useful for logging — operators care about both numbers because a
// hardlink-heavy image can have len(paths) ≫ Size.
func (b *BaseSet) PathCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.basePaths)
}
