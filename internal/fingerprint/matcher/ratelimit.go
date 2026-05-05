package matcher

import (
	"context"
	"sync"
	"time"
)

// RateLimitedMatcher wraps an inner Matcher with a token-bucket
// rate limiter so we don't DDoS public APIs (Software Heritage,
// ClearlyDefined). The limiter blocks the calling goroutine when
// the bucket is empty, respecting context cancellation.
//
// The default refill rate (5 tokens per second, burst 10) is set to
// public-API friendliness — both SWH and CD publish "be polite"
// guidance without hard limits, and we err on the slow side. Tune
// per Options when a use case has different needs.
type RateLimitedMatcher struct {
	inner Matcher

	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	clock      func() time.Time
}

// RateLimitOptions configures NewRateLimited.
type RateLimitOptions struct {
	// Burst is the maximum number of tokens. Zero -> 10.
	Burst int
	// PerSecond is the refill rate. Zero -> 5.
	PerSecond float64
	// Clock overrides time.Now for tests.
	Clock func() time.Time
}

// NewRateLimited returns a rate-limited wrapper around inner.
func NewRateLimited(inner Matcher, opts RateLimitOptions) *RateLimitedMatcher {
	burst := opts.Burst
	if burst <= 0 {
		burst = 10
	}
	rate := opts.PerSecond
	if rate <= 0 {
		rate = 5
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	return &RateLimitedMatcher{
		inner:      inner,
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: clock(),
		clock:      clock,
	}
}

// Name implements Matcher.
func (r *RateLimitedMatcher) Name() string { return r.inner.Name() + "[ratelimited]" }

// Lookup implements Matcher.
func (r *RateLimitedMatcher) Lookup(ctx context.Context, alg, digest string) (Match, error) {
	if err := r.acquire(ctx); err != nil {
		return Match{}, err
	}
	return r.inner.Lookup(ctx, alg, digest)
}

// acquire blocks until a token is available OR ctx is cancelled.
// Uses a 50 ms polling interval — cheap enough for the "occasional
// untracked-component lookup" volume Astinus generates.
func (r *RateLimitedMatcher) acquire(ctx context.Context) error {
	for {
		r.refill()
		r.mu.Lock()
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (r *RateLimitedMatcher) refill() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock()
	elapsed := now.Sub(r.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	r.tokens += elapsed * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefill = now
}
