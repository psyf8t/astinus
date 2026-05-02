package matcher

import (
	"context"
	"errors"
	"sync"
	"time"
)

// CachedMatcher wraps an inner Matcher with an in-memory TTL cache.
//
// Both successful matches and ErrNoMatch are cached so a registry
// hit AND a registry miss avoid re-querying for the same digest.
// Real errors (network failure, 5xx) are NOT cached — the next call
// gets to retry.
//
// The cache is shared by all callers of the same instance and
// tracked by `(alg, digest)` (case-normalised). Entries fall out of
// the cache when they age past TTL OR when MaxEntries is reached
// (oldest insertion evicted first). Both knobs are optional;
// reasonable defaults apply.
type CachedMatcher struct {
	inner Matcher

	ttl        time.Duration
	maxEntries int

	mu      sync.RWMutex
	entries map[string]cachedEntry
	order   []string
	clock   func() time.Time
}

type cachedEntry struct {
	match  Match
	err    error // ErrNoMatch only; real errors aren't cached
	insert time.Time
}

// CacheOptions configures NewCached.
type CacheOptions struct {
	// TTL is the per-entry expiry. Zero -> 1 hour.
	TTL time.Duration
	// MaxEntries caps the cache size. Zero -> 4096.
	MaxEntries int
	// Clock overrides time.Now for tests.
	Clock func() time.Time
}

// NewCached returns a CachedMatcher wrapping inner.
func NewCached(inner Matcher, opts CacheOptions) *CachedMatcher {
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 4096
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &CachedMatcher{
		inner:      inner,
		ttl:        opts.TTL,
		maxEntries: opts.MaxEntries,
		entries:    make(map[string]cachedEntry, opts.MaxEntries),
		clock:      opts.Clock,
	}
}

// Name implements Matcher.
func (c *CachedMatcher) Name() string { return c.inner.Name() + "[cached]" }

// Lookup implements Matcher.
func (c *CachedMatcher) Lookup(ctx context.Context, alg, digest string) (Match, error) {
	key := localKey(alg, digest)

	if entry, ok := c.read(key); ok {
		return entry.match, entry.err
	}

	match, err := c.inner.Lookup(ctx, alg, digest)
	if err != nil && !isNoMatch(err) {
		// Don't cache real errors — let the next call retry.
		return match, err
	}
	c.store(key, cachedEntry{match: match, err: err, insert: c.clock()})
	return match, err
}

func (c *CachedMatcher) read(key string) (cachedEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return cachedEntry{}, false
	}
	if c.clock().Sub(entry.insert) > c.ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return cachedEntry{}, false
	}
	return entry, true
}

func (c *CachedMatcher) store(key string, entry cachedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.maxEntries {
			// Drop the oldest insertion. Tiny FIFO; not LRU because
			// LRU's bookkeeping isn't worth it for the small
			// `maxEntries` we expect.
			if len(c.order) > 0 {
				oldest := c.order[0]
				c.order = c.order[1:]
				delete(c.entries, oldest)
			}
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = entry
}

// Len reports how many entries the cache currently holds.
func (c *CachedMatcher) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// isNoMatch reports whether err wraps ErrNoMatch.
func isNoMatch(err error) bool { return errors.Is(err, ErrNoMatch) }
