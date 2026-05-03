package policy

// Severity is the gravity of a Finding.
//
// Order matters — `Severity.AtLeast` compares ordinal positions so
// callers can write `s.AtLeast(SeverityHigh)` without enumerating
// values.
type Severity int

// Recognised severities, in ascending order.
const (
	// SeverityInfo is informational; never blocks a `--fail-on` gate.
	SeverityInfo Severity = iota
	// SeverityLow is a minor compliance gap (e.g. missing
	// vulnerability-disclosure URL on a third-party library).
	SeverityLow
	// SeverityMedium covers gaps that an enterprise auditor would
	// flag but that are recoverable (missing supplier name on a
	// known-vendor package).
	SeverityMedium
	// SeverityHigh is a violation an auditor will not let pass
	// (missing version on a Component, missing SBOM Author).
	SeverityHigh
	// SeverityCritical is a structural failure (Component without
	// a Name, malformed CycloneDX shape).
	SeverityCritical
)

// String renders the severity as the lowercase name used in
// SBOM properties (`astinus:compliance:critical-count`,
// `astinus:compliance:findings-count`) and the `--fail-on`
// flag's accepted values.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// AtLeast reports whether s is at the same or higher severity than
// floor. Used by the `--fail-on` gate: any finding `s.AtLeast(floor)`
// triggers a non-zero exit.
func (s Severity) AtLeast(floor Severity) bool { return s >= floor }

// ParseSeverity returns the Severity for the lowercase string name
// (`critical` / `high` / `medium` / `low` / `info`). Unknown
// values yield SeverityInfo + ok=false so callers can decide
// whether to default or error.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "critical":
		return SeverityCritical, true
	case "high":
		return SeverityHigh, true
	case "medium":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	case "info", "":
		return SeverityInfo, true
	default:
		return SeverityInfo, false
	}
}

// Finding is one validation result.
type Finding struct {
	// Severity is the gravity (info … critical).
	Severity Severity

	// RuleID is the stable identifier for the check that produced
	// this finding (e.g. `NTIA-VERSION`, `EU-CRA-ART13-VULN`).
	// Operators consume this for filtering / triage.
	RuleID string

	// Component is the BOMRef of the offending component when the
	// finding is per-component. Empty when the finding is
	// SBOM-level (missing Author, missing Timestamp).
	Component string

	// Message is the human-readable description.
	Message string

	// Reference is a citation (regulation paragraph, NTIA element
	// number) that explains WHY this matters.
	Reference string
}
