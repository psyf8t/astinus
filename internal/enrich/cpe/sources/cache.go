package sources

import (
	"sync"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// Cache is the in-memory PURL → []Match memo the orchestrator
// consults before walking the Source chain.
//
// The cache is per-orchestrator (per-enricher invocation). It is NOT
// persisted across runs — that's documented as future work in
// ADR-0023. Operators who want persistence can use the existing
// offline-db (Stage 12 LocalDictionaryResolver, exposed here as
// the LocalDictSource).
//
// Concurrency: safe for concurrent use.
type Cache struct {
	mu      sync.RWMutex
	entries map[string][]cpe.Match
}

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return &Cache{entries: map[string][]cpe.Match{}}
}

// Get returns the cached candidates for purl plus a hit indicator.
// A hit with an empty slice means "we resolved this PURL before and
// nobody had anything to say"; the orchestrator should not re-walk
// the chain.
func (c *Cache) Get(purl string) ([]cpe.Match, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[purl]
	return v, ok
}

// Set stores matches under purl.
func (c *Cache) Set(purl string, matches []cpe.Match) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[purl] = matches
}

// Size reports the number of cached entries.
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
