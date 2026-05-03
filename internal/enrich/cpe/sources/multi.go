package sources

import (
	"context"
	"log/slog"
	"sort"

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
}

// NewMultiSource returns a MultiSourceResolver configured per opts.
//
// Sources are sorted by Priority descending. When mode is
// ModeOffline, Sources whose RequiresNetwork returns true are
// dropped at registration; the resolver then guarantees zero
// outbound HTTP calls.
func NewMultiSource(opts Options) *MultiSourceResolver {
	mode := opts.Mode
	if !mode.IsKnown() {
		mode = ModeHybrid
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cache := opts.Cache
	if cache == nil {
		cache = NewCache()
	}
	out := &MultiSourceResolver{mode: mode, logger: logger, cache: cache}
	for _, s := range opts.Sources {
		if s == nil {
			continue
		}
		if mode == ModeOffline && s.RequiresNetwork() {
			continue
		}
		out.sources = append(out.sources, s)
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

// Resolve implements `cpe.Resolver`.
//
// Strategy:
//
//  1. Cache check — if we've resolved this PURL before, return.
//  2. For each Source (in priority order, Mode-filtered):
//     - Call Match. Errors are logged and dropped (the chain
//     continues with the next Source).
//     - Append every returned Match to the accumulator.
//     - When Mode == ModeHybrid AND we have at least one
//     high-confidence offline match, stop walking online
//     Sources — we don't pay the network cost when offline
//     already gave us an authoritative answer.
//  3. Cache the result (including the empty case) so a second
//     component with the same PURL doesn't re-walk.
func (r *MultiSourceResolver) Resolve(p cpe.PURL) []cpe.Match {
	return r.resolveCtx(context.Background(), p)
}

// ResolveCtx is the context-aware variant of Resolve. The legacy
// `cpe.Resolver` interface drops ctx; the orchestrator's HTTP
// Sources need it for cancellation, so we fabricate a Background
// context in Resolve and surface ResolveCtx for callers that hold a
// real context.
func (r *MultiSourceResolver) ResolveCtx(ctx context.Context, p cpe.PURL) []cpe.Match {
	return r.resolveCtx(ctx, p)
}

func (r *MultiSourceResolver) resolveCtx(ctx context.Context, p cpe.PURL) []cpe.Match {
	key := purlCacheKey(p)
	if cached, ok := r.cache.Get(key); ok {
		return cached
	}

	var all []cpe.Match
	haveOfflineHigh := false
	for _, src := range r.sources {
		// In hybrid mode, skip online sources when an offline
		// source has already produced a high-confidence answer.
		if r.mode == ModeHybrid && haveOfflineHigh && src.RequiresNetwork() {
			continue
		}
		matches, err := src.Match(ctx, p)
		if err != nil {
			r.logger.Debug("cpe.source.error",
				"source", src.Name(),
				"purl", key,
				"err", err.Error())
			continue
		}
		if len(matches) == 0 {
			continue
		}
		all = append(all, matches...)
		if !src.RequiresNetwork() && hasHighConfidence(matches) {
			haveOfflineHigh = true
		}
	}

	r.cache.Set(key, all)
	return all
}

// purlCacheKey is the stable cache lookup key for a PURL.
// Kept to (type, namespace, name, version) — qualifiers don't
// affect CPE resolution.
func purlCacheKey(p cpe.PURL) string {
	out := p.Type + "|" + p.Namespace + "|" + p.Name + "|" + p.Version
	return out
}

// hasHighConfidence reports whether matches contains at least one
// `ConfidenceHigh` entry.
func hasHighConfidence(matches []cpe.Match) bool {
	for _, m := range matches {
		if m.Confidence == cpe.ConfidenceHigh {
			return true
		}
	}
	return false
}
