package model

// License represents one entry in a Component.Licenses list.
//
// CycloneDX models a license either as a structured License (with SPDX
// id, name, url, text) OR as a free-form SPDX expression
// ("MIT OR Apache-2.0"). We keep both shapes accessible: an entry with
// Expression set is the expression case, otherwise SPDXID/Name carry
// the structured form. SPDX inputs map onto the same shape.
type License struct {
	// SPDXID is the SPDX short identifier (e.g. "MIT", "Apache-2.0").
	SPDXID string

	// Name is the human-readable name when no SPDX id is known
	// (e.g. "Custom Corporate License").
	Name string

	// Expression is a SPDX license expression
	// (https://spdx.dev/learn/handling-license-info/).
	Expression string

	// URL is the canonical URL for the license text. Optional.
	URL string
}

// IsExpression reports whether the license is recorded as an SPDX
// expression rather than a structured license.
func (l License) IsExpression() bool {
	return l.Expression != ""
}

// IsEmpty reports whether the license has no useful information.
func (l License) IsEmpty() bool {
	return l.SPDXID == "" && l.Name == "" && l.Expression == "" && l.URL == ""
}
