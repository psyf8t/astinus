package sources

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// MultiSourceResolver implements `cpe.Resolver` (the existing
// enricher contract) by walking a chain of Sources.
//
// The resolver is constructed once at CLI start-up; the enricher
// passes parsed PURLs to `Resolve` (the legacy interface) and the
// orchestrator translates that into per-Source `Match` calls.
//
// Concurrency: safe for concurrent use after construction.
type MultiSourceResolver struct {
	sources []Source
	mode    Mode
	cache   *Cache
	logger  *slog.Logger

	// Per-source budgets. Populated when Options.PerSourceTimeout or
	// PerCallTimeout is non-zero (CLI default since S6 Task 0).
	// Zero-value-empty map ⇒ no budget enforcement (legacy / tests).
	budgets map[string]*SourceBudget

	// statusMu guards statuses; tracking is read by the CLI layer
	// at end-of-run to stamp `astinus:cpe:source-status:<name>`.
	statusMu sync.Mutex
	statuses map[string]string
}

// Options configures a MultiSourceResolver.
type Options struct {
	// Mode selects which Sources run. Zero value is ModeHybrid.
	Mode Mode

	// Sources is the ordered set the resolver registers. Nil
	// entries are silently dropped (callers can pass
	// `NewLocalDict(nil)` when no offline-db is available).
	Sources []Source

	// Logger receives per-Source error / no-match debug records.
	// Nil means slog.Default().
	Logger *slog.Logger

	// Cache is the in-memory PURL → Matches memo. Nil means a
	// fresh empty cache is created.
	Cache *Cache

	// PerSourceTimeout caps the cumulative wall-time any single
	// online source can spend across an Enrich call. After the
	// budget elapses the source is marked exhausted and skipped
	// for the rest of the run. Zero disables (back-compat). The
	// CLI defaults to 60 s. S6 Task 0.
	PerSourceTimeout time.Duration

	// PerCallTimeout caps each individual outbound HTTP call. A
	// call that exceeds the deadline returns
	// context.DeadlineExceeded, which the resolver treats as
	// "source unavailable" — the budget is marked exhausted and
	// (in hybrid mode) the resolver propagates ErrSourceUnavailable.
	// Zero disables. The CLI defaults to 10 s. S6 Task 0.
	PerCallTimeout time.Duration
}

// ErrSourceUnavailable is returned from ResolveCtx when the resolver
// is in ModeHybrid / ModeOnline and an online source's call hit its
// per-call deadline (or the source's total budget elapsed). The
// enricher surfaces this to the CLI as exit code 60 per the
// `--cpe-mode hybrid` contract. ADR-0051 + ADR-0057.
var ErrSourceUnavailable = errors.New("cpe source unavailable")

// NewMultiSource returns a MultiSourceResolver configured per opts.
//
// Sources are sorted by Priority descending. When mode is
// ModeOffline, Sources whose RequiresNetwork returns true are
// dropped at registration; the resolver then guarantees zero
// outbound HTTP calls.
//
// S4 Task 4: the zero-value / unknown-Mode fallback is ModeAuto
// (was ModeHybrid). ModeHybrid now means strict — see
// EcosystemPolicy in the CLI layer.
//
// S6 Task 0: per-source + per-call timeouts wire into SourceBudget
// instances created here and consulted on every Source.Match call.
func NewMultiSource(opts Options) *MultiSourceResolver {
	mode := opts.Mode
	if !mode.IsKnown() {
		mode = ModeAuto
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cache := opts.Cache
	if cache == nil {
		cache = NewCache()
	}
	out := &MultiSourceResolver{
		mode:     mode,
		logger:   logger,
		cache:    cache,
		budgets:  map[string]*SourceBudget{},
		statuses: map[string]string{},
	}
	for _, s := range opts.Sources {
		if s == nil {
			continue
		}
		if mode == ModeOffline && s.RequiresNetwork() {
			continue
		}
		out.sources = append(out.sources, s)
		// Offline sources don't talk to the network — no budget
		// needed (token-bucket Wait etc. won't block on I/O).
		if s.RequiresNetwork() && (opts.PerSourceTimeout > 0 || opts.PerCallTimeout > 0) {
			out.budgets[s.Name()] = NewSourceBudget(
				s.Name(), opts.PerSourceTimeout, opts.PerCallTimeout)
		}
	}
	sort.SliceStable(out.sources, func(i, j int) bool {
		return out.sources[i].Priority() > out.sources[j].Priority()
	})
	return out
}

// Sources returns the registered Sources after Mode-filtering and
// priority sort. Useful for diagnostic CLI output.
func (r *MultiSourceResolver) Sources() []Source {
	out := make([]Source, len(r.sources))
	copy(out, r.sources)
	return out
}

// Mode returns the resolver's effective mode.
func (r *MultiSourceResolver) Mode() Mode { return r.mode }

// SourceStatuses returns a snapshot of the per-source completion
// status accumulated during this resolver's lifetime. Keys are
// source names; values are one of:
//
//   - "complete"                — source ran for every component.
//   - "budget-exhausted:<dur>"  — source.TotalDuration elapsed.
//   - "timeout"                 — single call hit per-call deadline.
//   - "errored"                 — last call returned a non-deadline error.
//
// The CLI stamps these as `astinus:cpe:source-status:<name>`
// properties at end of run. S6 Task 0 / ADR-0057.
func (r *MultiSourceResolver) SourceStatuses() map[string]string {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	out := make(map[string]string, len(r.statuses))
	for k, v := range r.statuses {
		out[k] = v
	}
	return out
}

// recordStatus stamps name → status, but only if the source doesn't
// already carry a terminal status (we don't want a stale "complete"
// overriding "budget-exhausted").
func (r *MultiSourceResolver) recordStatus(name, status string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	if existing, ok := r.statuses[name]; ok && isTerminalStatus(existing) {
		return
	}
	r.statuses[name] = status
}

// isTerminalStatus reports whether a recorded status is sticky — i.e.
// further updates from the same source shouldn't overwrite it. The
// "complete" stamp is provisional (re-emitted on every component);
// budget-exhausted / timeout / errored are sticky.
func isTerminalStatus(s string) bool {
	return s != "" && s != "complete"
}

// Resolve implements `cpe.Resolver`.
//
// Strategy:
//
//  1. Cache check — if we've resolved this PURL before, return.
//  2. For each Source (in priority order, Mode-filtered):
//     - Call Match. Errors are logged and dropped (the chain
//     continues with the next Source).
//     - Append every returned Candidate to the accumulator.
//     - When Mode == ModeHybrid AND we have at least one
//     high-confidence offline match, stop walking online
//     Sources — we don't pay the network cost when offline
//     already gave us an authoritative answer.
//  3. Cache the result (including the empty case) so a second
//     component with the same PURL doesn't re-walk.
func (r *MultiSourceResolver) Resolve(p cpe.PURL) []cpe.Candidate {
	cands, _ := r.resolveCtx(context.Background(), p)
	return cands
}

// ResolveCtx is the context-aware variant of Resolve. The legacy
// `cpe.Resolver` interface drops ctx; the orchestrator's HTTP
// Sources need it for cancellation, so we fabricate a Background
// context in Resolve and surface ResolveCtx for callers that hold a
// real context.
//
// S6 Task 0: returns (candidates, error). In ModeHybrid / ModeOnline
// a single per-call timeout produces ErrSourceUnavailable so the
// enricher can convert that to exit-60 per ADR-0051. In ModeAuto the
// error is always nil; the source is silently skipped for the rest
// of the run.
func (r *MultiSourceResolver) ResolveCtx(ctx context.Context, p cpe.PURL) ([]cpe.Candidate, error) {
	return r.resolveCtx(ctx, p)
}

func (r *MultiSourceResolver) resolveCtx(ctx context.Context, p cpe.PURL) ([]cpe.Candidate, error) {
	key := purlCacheKey(p)
	if cached, ok := r.cache.Get(key); ok {
		return cached, nil
	}

	var all []cpe.Candidate
	haveOfflineHigh := false
	for _, src := range r.sources {
		// In hybrid / auto mode, skip online sources when an offline
		// source has already produced a high-confidence answer.
		// ModeOnline keeps walking even when offline gave a high
		// match (operator explicitly asked for the full sweep). S4
		// Task 4: ModeAuto behaves like ModeHybrid here (the new
		// "strict" semantic only changes source-availability
		// handling, not the walk order).
		if shouldShortCircuitOnHigh(r.mode) && haveOfflineHigh && src.RequiresNetwork() {
			continue
		}

		cands, err := r.callSource(ctx, src, p)
		if errors.Is(err, ErrSourceUnavailable) {
			// Strict mode + this source timed out → propagate to the
			// enricher so it can exit 60. We DO drop everything we
			// gathered so far; ModeHybrid's contract is "all sources
			// available or no result".
			return nil, err
		}
		if errors.Is(err, ErrSourceBudgetExhausted) {
			continue
		}
		if err != nil {
			r.logger.Debug("cpe.source.error",
				"source", src.Name(),
				"purl", key,
				"err", err.Error())
			continue
		}
		if len(cands) == 0 {
			continue
		}
		all = append(all, cands...)
		if !src.RequiresNetwork() && hasHighConfidence(cands) {
			haveOfflineHigh = true
		}
	}

	r.cache.Set(key, all)
	return all, nil
}

// callSource invokes src.Match with a budget-bounded context when a
// per-source budget exists for it. Returns the candidates and
// classified error. Extracted from resolveCtx to keep cognitive
// complexity within the linter budget. S6 Task 0.
func (r *MultiSourceResolver) callSource(ctx context.Context, src Source, p cpe.PURL) ([]cpe.Candidate, error) {
	budget, hasBudget := r.budgets[src.Name()]
	if !hasBudget {
		// Offline source or no-timeout configuration. Run as before.
		cands, err := src.Match(ctx, p)
		if err == nil {
			r.recordStatus(src.Name(), "complete")
		}
		return cands, err
	}

	if budget.IsExhausted() {
		return nil, ErrSourceBudgetExhausted
	}

	callCtx, cancel, err := budget.AcquireCallDeadline(ctx)
	if err != nil {
		r.recordStatus(src.Name(),
			"budget-exhausted:"+budget.TotalDuration.String())
		return nil, err
	}
	defer cancel()

	cands, callErr := src.Match(callCtx, p)
	switch {
	case errors.Is(callErr, context.DeadlineExceeded):
		// The single call hit its deadline. We treat this as the
		// source being unavailable for the rest of the run — most
		// likely an idle TCP connection per the run-#4 reproducer.
		budget.MarkExhausted("timeout")
		r.recordStatus(src.Name(), "timeout")
		r.logger.Warn("cpe.source.call-timeout",
			"source", src.Name(),
			"per_call_timeout", budget.PerCallTimeout,
			"purl", purlCacheKey(p),
			"hint", "increase --cpe-call-timeout or use --cpe-mode offline")
		if r.mode.IsStrict() {
			return nil, ErrSourceUnavailable
		}
		return nil, nil
	case callErr != nil:
		r.recordStatus(src.Name(), "errored")
		return nil, callErr
	default:
		// Source ran; mark provisionally complete. A later call on
		// the same source might still exhaust the budget; the
		// recordStatus helper won't overwrite a terminal status.
		r.recordStatus(src.Name(), "complete")
		return cands, nil
	}
}

// shouldShortCircuitOnHigh reports whether the resolver should stop
// walking online sources once an offline source produced a
// high-confidence match. True for ModeAuto and ModeHybrid (the
// hybrid family); false for ModeOnline (operator asked for the full
// sweep) and ModeOffline (online sources already filtered out). S4
// Task 4.
func shouldShortCircuitOnHigh(m Mode) bool {
	return m == ModeAuto || m == ModeHybrid
}

// purlCacheKey is the stable cache lookup key for a PURL.
// Kept to (type, namespace, name, version) — qualifiers don't
// affect CPE resolution.
func purlCacheKey(p cpe.PURL) string {
	out := p.Type + "|" + p.Namespace + "|" + p.Name + "|" + p.Version
	return out
}

// hasHighConfidence reports whether cands contains at least one
// candidate scoring at or above the primary-min threshold. This
// gates the hybrid-mode early exit so we only skip online lookups
// when an offline source has produced a result good enough to be
// the Component's primary CPE.
func hasHighConfidence(cands []cpe.Candidate) bool {
	floor := cpe.DefaultThreshold().PrimaryMin
	for _, c := range cands {
		if c.Confidence >= floor {
			return true
		}
	}
	return false
}
