package lifecycle

import (
	"context"
	"errors"
	"time"
)

// Source is the per-Component lifecycle data adapter. Two
// implementations: EndOfLifeSource (online) and BundledSource
// (embedded snapshot).
//
// Concurrency: Fetch is called from the enricher hot loop;
// implementations MUST be safe for concurrent use.
type Source interface {
	// Name is the short identifier stamped onto
	// `astinus:lifecycle:source`.
	Name() string

	// Fetch returns the cycle entry that matches version (an
	// endoflife.date "cycle" key like "20" for Node 20). Returns
	// ErrNotFound when the product or cycle is unknown.
	Fetch(ctx context.Context, product, version string) (*Lifecycle, error)

	// RequiresNetwork reports whether Fetch makes outbound HTTP
	// calls. The Resolver filters network sources under
	// `--no-network`.
	RequiresNetwork() bool
}

// Lifecycle is one product's lifecycle data for a specific cycle.
// All date fields are time.Time; zero values mean "no data".
//
// Status is computed by the Resolver after Fetch returns so the
// "now" reference is consistent across the run.
type Lifecycle struct {
	// Cycle is the endoflife.date cycle key the version matched
	// against (e.g. "20" for Node 20.x.y).
	Cycle string

	// ReleaseDate is when this cycle was first released. Zero
	// when the source didn't carry the field.
	ReleaseDate time.Time

	// ActiveSupportEnd is when active support ended (or will end).
	// After this date the cycle enters maintenance mode.
	ActiveSupportEnd time.Time

	// EOL is the end-of-life date. After this date the cycle is
	// considered EOL — no security patches expected.
	EOL time.Time

	// EOLBoolean — endoflife.date sometimes records `eol: true`
	// (EOL date unknown) or `eol: false` (definitely not EOL,
	// no scheduled date). Captured here so the projection can
	// surface "true" / "false" instead of an empty value.
	EOLBoolean string // "" | "true" | "false"

	// SupportBoolean — same shape for the active-support field.
	SupportBoolean string // "" | "true" | "false"

	// Latest is the most recent release in this cycle (e.g.
	// "20.18.0"). Optional.
	Latest string

	// LTS reports whether the cycle is a Long-Term-Support
	// release.
	LTS bool
}

// Status is the Resolver's classification of a Lifecycle as of the
// run's reference clock.
type Status string

// Recognised statuses.
const (
	// StatusActive — release date in the past, active support
	// either has no end recorded or hasn't been reached.
	StatusActive Status = "active"

	// StatusMaintenance — past active support but before EOL.
	StatusMaintenance Status = "maintenance"

	// StatusEOL — past EOL (production should plan migration).
	StatusEOL Status = "eol"

	// StatusUnknown — Lifecycle data is too sparse to classify.
	StatusUnknown Status = "unknown"
)

// ClassifyStatus computes the Status of l as of now. Used by both
// the Resolver and tests so the rules live in one place.
func ClassifyStatus(l *Lifecycle, now time.Time) Status {
	if l == nil {
		return StatusUnknown
	}
	if !l.EOL.IsZero() && !now.Before(l.EOL) {
		return StatusEOL
	}
	if l.EOLBoolean == "true" {
		return StatusEOL
	}
	if !l.ActiveSupportEnd.IsZero() && !now.Before(l.ActiveSupportEnd) {
		return StatusMaintenance
	}
	if l.SupportBoolean == "false" && l.EOLBoolean != "true" {
		return StatusMaintenance
	}
	if !l.ReleaseDate.IsZero() {
		return StatusActive
	}
	return StatusUnknown
}

// DaysUntilEOL returns the signed day count from now to EOL.
// Negative = past EOL. Returns 0 + ok=false when EOL is unknown
// (caller stamps "unknown" instead of "0").
func DaysUntilEOL(l *Lifecycle, now time.Time) (int, bool) {
	if l == nil || l.EOL.IsZero() {
		return 0, false
	}
	delta := l.EOL.Sub(now)
	return int(delta / (24 * time.Hour)), true
}

// Mode controls which Sources the Resolver runs. Mirrors the
// `cpe/sources.Mode` pattern (PRSD-Task-5).
type Mode string

// Recognised modes.
const (
	// ModeOnline runs only EndOfLifeSource (no fallback to
	// bundled). Used when operators want the freshest data and
	// don't trust the bundled snapshot.
	ModeOnline Mode = "online"

	// ModeOffline runs only BundledSource (no network). Used
	// under `--no-network` and air-gapped environments.
	ModeOffline Mode = "offline"

	// ModeHybrid (default) tries the online source first; on
	// ErrNotFound or ErrTransient, falls back to the bundled
	// snapshot.
	ModeHybrid Mode = "hybrid"
)

// IsKnown reports whether m is a recognised mode value.
func (m Mode) IsKnown() bool {
	switch m {
	case ModeOnline, ModeOffline, ModeHybrid:
		return true
	default:
		return false
	}
}

// EffectiveMode returns ModeHybrid when m is empty.
func (m Mode) EffectiveMode() Mode {
	if m == "" {
		return ModeHybrid
	}
	return m
}

// Sentinel errors. Implementations wrap their internal errors with
// errors.Join so the Resolver can branch on errors.Is.
var (
	// ErrNotFound — the product or cycle is unknown.
	ErrNotFound = errors.New("lifecycle: not found")

	// ErrTransient — temporary network failure (5xx, timeout,
	// rate-limit denial). Resolver may fall back to bundled.
	ErrTransient = errors.New("lifecycle: transient failure")

	// ErrUnsupported — the Component cannot be mapped to an
	// endoflife.date product. The Resolver treats this as a
	// silent skip (no log spam — most Components in a typical
	// SBOM aren't OS/runtime).
	ErrUnsupported = errors.New("lifecycle: component not lifecycle-mapped")
)
