package sources

import (
	"context"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// Mode controls which Sources the orchestrator runs.
//
// Operators choose the mode via `--cpe-mode`. The default is
// ModeAuto since S4 Task 4: do the best with whatever online
// sources are reachable, skip the rest with a WARN log.
// ModeHybrid is the strict variant — fails fast (exit 60) when any
// expected online source is unavailable.
type Mode string

// Recognised modes.
const (
	// ModeOffline runs only Sources whose RequiresNetwork() is
	// false. Guaranteed to make zero outbound HTTP calls.
	ModeOffline Mode = "offline"

	// ModeAuto runs every reachable Source and skips unavailable
	// ones with a WARN log. The current default — picks up the
	// graceful-degradation behaviour earlier revisions had under
	// "hybrid" (silently dropping NVD when the workload would wedge
	// the anonymous rate limit). S4 Task 4.
	ModeAuto Mode = "auto"

	// ModeOnline is the deprecated alias for ModeHybrid. Kept so
	// scripts that pass `--cpe-mode online` keep working through
	// v0.0.x; will be removed in v1.0.0. The orchestrator treats
	// it identically to ModeHybrid.
	ModeOnline Mode = "online"

	// ModeHybrid is the strict variant: every recognised online
	// source MUST be reachable, or the CLI exits 60 with an
	// actionable error. S4 Task 4 flipped the semantics from the
	// pre-S4 "graceful degradation" shape, which now lives under
	// ModeAuto.
	ModeHybrid Mode = "hybrid"
)

// IsKnown reports whether m is a recognised mode value.
func (m Mode) IsKnown() bool {
	switch m {
	case ModeOffline, ModeAuto, ModeOnline, ModeHybrid:
		return true
	default:
		return false
	}
}

// IsStrict reports whether m requires every recognised online
// source to be available — i.e. unavailability is a fail-fast
// condition rather than a WARN-and-continue. True for ModeHybrid
// and the deprecated ModeOnline alias. S4 Task 4.
func (m Mode) IsStrict() bool { return m == ModeHybrid || m == ModeOnline }

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
