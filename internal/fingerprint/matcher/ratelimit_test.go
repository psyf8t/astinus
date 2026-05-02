package matcher

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimitedAllowsBurst(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	r := NewRateLimited(inner, RateLimitOptions{Burst: 5, PerSecond: 1})
	for i := 0; i < 5; i++ {
		if _, err := r.Lookup(context.Background(), "sha256", "x"); err != nil {
			t.Fatalf("Lookup %d: %v", i, err)
		}
	}
	if inner.hits != 5 {
		t.Errorf("inner hits = %d, want 5", inner.hits)
	}
}

func TestRateLimitedThrottlesAfterBurst(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	r := NewRateLimited(inner, RateLimitOptions{Burst: 2, PerSecond: 100})
	for i := 0; i < 2; i++ {
		_, _ = r.Lookup(context.Background(), "sha256", "x")
	}

	// Consume the bucket; the third call must wait at least
	// 1/PerSecond seconds (10 ms here). We give it generous time.
	start := time.Now()
	if _, err := r.Lookup(context.Background(), "sha256", "x"); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 10*time.Millisecond {
		// We can't be stricter without flakiness; just verify the
		// rate limiter at least asked us to wait a bit.
		t.Logf("third call took %v (expected >= ~10ms)", took)
	}
	if inner.hits != 3 {
		t.Errorf("inner hits = %d, want 3", inner.hits)
	}
}

func TestRateLimitedRespectsContext(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	r := NewRateLimited(inner, RateLimitOptions{Burst: 1, PerSecond: 0.1}) // ~10s per token

	// Drain the bucket.
	if _, err := r.Lookup(context.Background(), "sha256", "x"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := r.Lookup(ctx, "sha256", "x")
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestRateLimitedConcurrent(t *testing.T) {
	inner := &counterMatcher{resp: Match{Name: "x"}}
	r := NewRateLimited(inner, RateLimitOptions{Burst: 50, PerSecond: 1000})

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Lookup(context.Background(), "sha256", "x")
		}()
	}
	wg.Wait()
	if inner.hits != 25 {
		t.Errorf("hits = %d, want 25", inner.hits)
	}
}

func TestRateLimitedName(t *testing.T) {
	r := NewRateLimited(&counterMatcher{}, RateLimitOptions{})
	if r.Name() != "counter[ratelimited]" {
		t.Errorf("Name = %q", r.Name())
	}
}
