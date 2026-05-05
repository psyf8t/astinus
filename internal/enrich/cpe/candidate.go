package cpe

// Candidate is one CPE proposal for a Component, scored by the
// resolver / source that produced it.
//
// Confidence is a float in [0.0, 1.0]. A value below the orchestrator's
// AlternativeMin threshold (default 0.5) makes the candidate a
// "rejected" entry — it never lands in the Component's `cpe` field
// and only surfaces as an opt-in `astinus:cpe:rejected:N` property
// for diagnostics.
//
// Sprint 3 Task 0 fixes a v0.2 false-positive class (NVD keyword search
// returning Linksys router CPEs for Go binary `yq`): per-Candidate
// confidence + Source replaces the previous blanket
// `astinus:cpe:confidence=high` stamp that lumped good and bad
// proposals together. See ADR-0029.
type Candidate struct {
	// CPE is the canonical 2.3 URI.
	CPE string `json:"cpe"`

	// Confidence in [0.0, 1.0]. Higher = stronger match.
	Confidence float64 `json:"confidence"`

	// Source identifies the producer ("nvd-api", "bundled",
	// "heuristic", "clearly-defined", "local-dictionary", "input").
	Source Source `json:"source"`

	// Evidence is a short human-readable note explaining why this
	// CPE was proposed. Optional.
	Evidence string `json:"evidence,omitempty"`

	// RejectedReason is filled by the scorer or by Classify when the
	// candidate sits below the orchestrator's AlternativeMin
	// threshold. Empty for kept candidates.
	RejectedReason string `json:"rejected_reason,omitempty"`

	// MatchDetails capture the per-attribute reasoning behind
	// Confidence. Used by `--include-rejected-cpe` debug output and
	// by future policy rules.
	MatchDetails MatchDetails `json:"match_details,omitempty"`
}

// MatchDetails records per-attribute match strength so operators can
// diagnose why a candidate scored what it did. Populated by sources
// that perform a weighted scoring (today: NVDAPISource); other sources
// leave it zero-valued.
type MatchDetails struct {
	// VendorMatch / ProductMatch describe how the CPE attribute
	// compared to the PURL: "exact" | "case-insensitive" |
	// "normalized" | "known-mapping" | "substring" | "fuzzy" |
	// "no-match".
	VendorMatch  string `json:"vendor_match,omitempty"`
	ProductMatch string `json:"product_match,omitempty"`

	// VersionMatch: "exact" | "wildcard" | "range" | "mismatch".
	VersionMatch string `json:"version_match,omitempty"`

	// SearchMethod identifies the lookup strategy that produced the
	// candidate ("purl-direct" | "keyword-search" |
	// "dictionary-lookup").
	SearchMethod string `json:"search_method,omitempty"`
}

// Match is retained as a deprecated alias for Candidate so that older
// call-sites and tests compile without churn while the codebase
// migrates to the richer name. New code should use Candidate.
type Match = Candidate
