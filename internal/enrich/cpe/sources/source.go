package sources

import (
	"context"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// Mode controls which Sources the orchestrator runs.
//
// Operators choose the mode via `--cpe-mode`. The default is
// ModeHybrid: offline first (cheap, deterministic), online for
// the long tail.
type Mode string

// Recognised modes.
const (
	// ModeOffline runs only Sources whose RequiresNetwork() is
	// false. Guaranteed to make zero outbound HTTP calls.
	ModeOffline Mode = "offline"

	// ModeOnline runs every Source — offline AND online. Network
	// failures degrade per-Source (the orchestrator continues with
	// the next Source).
	ModeOnline Mode = "online"

	// ModeHybrid is ModeOffline-first: offline Sources run in
	// priority order, and online Sources only run when no offline
	// Source produced a high-confidence match. Default for
	// operators who didn't pass `--cpe-mode`.
	ModeHybrid Mode = "hybrid"
)

// IsKnown reports whether m is a recognised mode value.
func (m Mode) IsKnown() bool {
	switch m {
	case ModeOffline, ModeOnline, ModeHybrid:
		return true
	default:
		return false
	}
}

// Source is one backend the orchestrator queries to resolve a PURL
// into CPE candidates.
//
// Concurrency: Match is called from the enricher's hot loop; Sources
// MUST be safe for concurrent use after construction.
//
// Err handling: a Source returns an error only when the underlying
// system is broken in a way the operator should know about (corrupt
// dictionary, malformed API response). Returning an error does NOT
// abort the orchestrator — the next Source still runs. A Source that
// has nothing to say returns `(nil, nil)`.
type Source interface {
	// Name is the short identifier used in logs and stamped onto
	// `astinus:cpe:source` Component properties.
	Name() string

	// Match returns 0 or more Candidate proposals for the parsed
	// PURL. The orchestrator deduplicates and classifies by
	// confidence downstream (cpe.DedupeCandidates + cpe.Classify),
	// so Sources are free to return overlapping CPEs with their own
	// per-candidate confidence + provenance.
	Match(ctx context.Context, p cpe.PURL) ([]cpe.Candidate, error)

	// RequiresNetwork is true for Sources whose Match makes outbound
	// HTTP calls. The orchestrator filters these out in ModeOffline
	// before invoking Match.
	RequiresNetwork() bool

	// Priority orders Sources within a mode. Higher = checked first.
	// Tie-broken by the order Sources were registered.
	//
	// Conventional values:
	//   100 — bundled hand-curated (highest precision; offline)
	//    90 — local dictionary (operator-supplied; offline)
	//    80 — NVD API (canonical, online)
	//    70 — ClearlyDefined (best-effort, online)
	//    50 — heuristic fallback (always-on; offline)
	Priority() int
}
