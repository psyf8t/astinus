package sources

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrSourceBudgetExhausted is returned by SourceBudget.AcquireCallDeadline
// when the source has spent its total time budget. Callers in the
// resolver chain skip the source for the remainder of the run when
// they see this error. S6 Task 0.
var ErrSourceBudgetExhausted = errors.New("cpe source budget exhausted")

// SourceBudget enforces two wall-time bounds on a CPE Source's
// outbound calls:
//
//   - TotalDuration is the cumulative budget across every call this
//     run; once exhausted the Source is marked done and skipped for
//     subsequent components.
//   - PerCallTimeout is the deadline applied to each individual call
//     (typically translated into the request's context.Context).
//
// The two bounds compose: each acquired deadline is the smaller of
// PerCallTimeout and the time remaining in TotalDuration.
//
// SourceBudget is safe for concurrent use after construction —
// MultiSourceResolver currently resolves one PURL at a time, but
// the budget guards against future parallelism without re-design.
//
// Background: run #4 multi-image benchmark showed `--cpe-mode auto`
// hanging > 19 minutes on an established but idle TCP connection
// to a Cloudflare-fronted CPE source. The bare http.Client.Timeout
// covers the body-read phase but didn't catch the deeper case (rate
// limiter `Wait` blocking on context.Background plumbed by the
// pre-S6 Resolver shim). ADR-0057.
type SourceBudget struct {
	Name           string
	TotalDuration  time.Duration
	PerCallTimeout time.Duration

	mu        sync.Mutex
	started   time.Time
	exhausted bool
	// reason records why the budget became exhausted: "elapsed"
	// (TotalDuration reached) or "timeout" (a single call hit its
	// deadline and the caller chose to drop the source). Empty
	// while the budget is still live.
	reason string
}

// NewSourceBudget returns a SourceBudget for the named source with
// the two bounds. Either bound may be zero, in which case it's
// treated as unlimited (the caller is expected to set both for
// production use — the resolver does that).
func NewSourceBudget(name string, total, perCall time.Duration) *SourceBudget {
	return &SourceBudget{
		Name:           name,
		TotalDuration:  total,
		PerCallTimeout: perCall,
	}
}

// Begin records the start of the source's enrichment phase. Must be
// called before the first AcquireCallDeadline. Idempotent — second
// call is a no-op so the resolver can call it once per Resolve
// without tracking state.
func (b *SourceBudget) Begin() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started.IsZero() {
		b.started = time.Now()
	}
}

// AcquireCallDeadline returns a child context bounded by the smaller
// of PerCallTimeout and the time remaining in TotalDuration. When
// the budget is already exhausted, returns the parent unchanged plus
// ErrSourceBudgetExhausted and a no-op cancel (the caller must not
// proceed with the call).
//
// The returned cancel func MUST be called by the caller — failing
// to do so leaks the timer until the parent context is cancelled.
func (b *SourceBudget) AcquireCallDeadline(parent context.Context) (
	context.Context, context.CancelFunc, error,
) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.exhausted {
		return parent, func() {}, ErrSourceBudgetExhausted
	}
	if b.started.IsZero() {
		b.started = time.Now()
	}
	if b.TotalDuration > 0 {
		elapsed := time.Since(b.started)
		if elapsed >= b.TotalDuration {
			b.exhausted = true
			b.reason = "elapsed"
			return parent, func() {}, ErrSourceBudgetExhausted
		}
		remaining := b.TotalDuration - elapsed
		if b.PerCallTimeout == 0 || remaining < b.PerCallTimeout {
			ctx, cancel := context.WithTimeout(parent, remaining)
			return ctx, cancel, nil
		}
	}
	if b.PerCallTimeout > 0 {
		ctx, cancel := context.WithTimeout(parent, b.PerCallTimeout)
		return ctx, cancel, nil
	}
	return parent, func() {}, nil
}

// MarkExhausted forces the budget closed with the given reason.
// Called by the resolver when a single call returns
// context.DeadlineExceeded and the operator's mode treats that as
// "source unavailable" rather than a transient retry.
func (b *SourceBudget) MarkExhausted(reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.exhausted {
		b.exhausted = true
		b.reason = reason
	}
}

// IsExhausted reports whether the budget has been closed (either by
// TotalDuration elapsing or via MarkExhausted).
func (b *SourceBudget) IsExhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exhausted
}

// Reason returns the close reason ("elapsed" or "timeout" or
// whatever MarkExhausted was called with). Empty while live.
func (b *SourceBudget) Reason() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reason
}

// Elapsed returns how long the budget has been running. Zero before
// Begin / first AcquireCallDeadline.
func (b *SourceBudget) Elapsed() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started.IsZero() {
		return 0
	}
	return time.Since(b.started)
}
