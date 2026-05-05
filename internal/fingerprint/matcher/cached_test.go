package matcher

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type counterMatcher struct {
	mu      sync.Mutex
	hits    int
	resp    Match
	respErr error
}

func (c *counterMatcher) Name() string { return "counter" }
func (c *counterMatcher) Lookup(_ context.Context, _, _ string) (Match, error) {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return c.resp, c.respErr
}

func TestCachedMatcherCachesHits(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	c := NewCached(inner, CacheOptions{TTL: time.Hour})

	for i := 0; i < 5; i++ {
		got, err := c.Lookup(context.Background(), "sha256", "abc")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.Name != "x" {
			t.Errorf("got %+v", got)
		}
	}
	if inner.hits != 1 {
		t.Errorf("inner hits = %d, want 1", inner.hits)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d", c.Len())
	}
}

func TestCachedMatcherCachesNoMatch(t *testing.T) {
	inner := &counterMatcher{respErr: ErrNoMatch}
	c := NewCached(inner, CacheOptions{TTL: time.Hour})

	for i := 0; i < 3; i++ {
		_, err := c.Lookup(context.Background(), "sha256", "x")
		if !errors.Is(err, ErrNoMatch) {
			t.Errorf("err = %v", err)
		}
	}
	if inner.hits != 1 {
		t.Errorf("ErrNoMatch should be cached: hits = %d", inner.hits)
	}
}

func TestCachedMatcherDoesNotCacheRealErrors(t *testing.T) {
	want := errors.New("kaboom")
	inner := &counterMatcher{respErr: want}
	c := NewCached(inner, CacheOptions{TTL: time.Hour})

	for i := 0; i < 3; i++ {
		_, err := c.Lookup(context.Background(), "sha256", "x")
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want kaboom", err)
		}
	}
	if inner.hits != 3 {
		t.Errorf("real errors should NOT be cached: hits = %d", inner.hits)
	}
}

func TestCachedMatcherTTLExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	inner := &counterMatcher{resp: Match{Name: "x"}}
	c := NewCached(inner, CacheOptions{TTL: 100 * time.Millisecond, Clock: clock})

	if _, err := c.Lookup(context.Background(), "sha256", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup(context.Background(), "sha256", "k"); err != nil {
		t.Fatal(err)
	}
	if inner.hits != 1 {
		t.Errorf("expected 1 hit so far, got %d", inner.hits)
	}

	// Advance the clock past TTL.
	now = now.Add(200 * time.Millisecond)
	if _, err := c.Lookup(context.Background(), "sha256", "k"); err != nil {
		t.Fatal(err)
	}
	if inner.hits != 2 {
		t.Errorf("expected re-fetch after TTL, hits = %d", inner.hits)
	}
}

func TestCachedMatcherEvictsOldestWhenFull(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	c := NewCached(inner, CacheOptions{TTL: time.Hour, MaxEntries: 3})

	for i, k := range []string{"a", "b", "c", "d"} {
		_, _ = c.Lookup(context.Background(), "sha256", k)
		_ = i
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3 (cap)", c.Len())
	}
	// "a" should have been evicted; lookup hits inner again.
	prevHits := inner.hits
	_, _ = c.Lookup(context.Background(), "sha256", "a")
	if inner.hits != prevHits+1 {
		t.Errorf("expected re-fetch for evicted entry, hits delta = %d", inner.hits-prevHits)
	}
}

func TestCachedMatcherName(t *testing.T) {
	inner := &counterMatcher{}
	c := NewCached(inner, CacheOptions{})
	if c.Name() != "counter[cached]" {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestCachedMatcherDefaults(t *testing.T) {
	c := NewCached(&counterMatcher{}, CacheOptions{})
	if c.ttl == 0 || c.maxEntries == 0 || c.clock == nil {
		t.Errorf("defaults not applied: ttl=%v max=%d", c.ttl, c.maxEntries)
	}
}

func TestIsNoMatchUnwraps(t *testing.T) {
	if isNoMatch(errors.New("plain")) {
		t.Error("non-NoMatch error should be false")
	}
	if !isNoMatch(ErrNoMatch) {
		t.Error("bare ErrNoMatch should be true")
	}
	if !isNoMatch(wrapNoMatch()) {
		t.Error("wrapped ErrNoMatch should be true")
	}
}

func wrapNoMatch() error {
	return wrapped{ErrNoMatch}
}

type wrapped struct{ inner error }

func (w wrapped) Error() string { return "wrap: " + w.inner.Error() }
func (w wrapped) Unwrap() error { return w.inner }
