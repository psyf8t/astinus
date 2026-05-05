package sources

import (
	"context"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// PatternMatcher is the always-on offline Source backed by the
// embedded `purl_to_cpe.json` mapping plus the heuristic name=name
// fallback. Wraps the existing `cpe.BundledResolver` and
// `cpe.HeuristicResolver` so the new Source-driven orchestrator can
// pick up the same answers the legacy chain produced.
//
// Two priority tiers are exposed via separate Source values
// (`NewPatternMatcher` for the bundled tier; `NewHeuristic` for the
// fallback). Splitting them lets operators see the heuristic firing
// in stats and lets the orchestrator early-exit on a high-confidence
// bundled match without paying for the heuristic call.
type PatternMatcher struct {
	resolver *cpe.BundledResolver
}

// NewPatternMatcher returns the always-on bundled-mapping Source.
//
// The bundled JSON is //go:embed-validated at build time; this
// constructor never fails.
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{resolver: cpe.NewBundledResolver()}
}

// Name implements Source.
func (*PatternMatcher) Name() string { return "pattern-matcher" }

// Match implements Source.
func (p *PatternMatcher) Match(_ context.Context, purl cpe.PURL) ([]cpe.Candidate, error) {
	return p.resolver.Resolve(purl), nil
}

// RequiresNetwork implements Source.
func (*PatternMatcher) RequiresNetwork() bool { return false }

// Priority implements Source — bundled mapping is the highest-precision
// source we have.
func (*PatternMatcher) Priority() int { return 100 }

// HeuristicSource emits a low-confidence vendor=name CPE for every
// PURL with a populated Name. Always last in the orchestrator chain
// so it only fires when nothing else matched.
type HeuristicSource struct {
	resolver *cpe.HeuristicResolver
}

// NewHeuristic returns the always-on heuristic fallback Source.
func NewHeuristic() *HeuristicSource {
	return &HeuristicSource{resolver: cpe.NewHeuristicResolver()}
}

// Name implements Source.
func (*HeuristicSource) Name() string { return "heuristic" }

// Match implements Source.
func (h *HeuristicSource) Match(_ context.Context, purl cpe.PURL) ([]cpe.Candidate, error) {
	return h.resolver.Resolve(purl), nil
}

// RequiresNetwork implements Source.
func (*HeuristicSource) RequiresNetwork() bool { return false }

// Priority implements Source — heuristic runs LAST among offline
// sources because anything more specific should win.
func (*HeuristicSource) Priority() int { return 50 }
