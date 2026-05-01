package model

// Evidence is provenance for a Component identification.
//
// CycloneDX 1.6 has a much richer Evidence shape (identity, occurrences,
// callstack). For MVP the canonical model only carries the three fields
// that downstream enrichers actually consume; the cyclonedx mapper
// preserves the original Evidence on the round-trip via SourceRaw when
// the writer can use it.
type Evidence struct {
	// Method describes how the component was identified
	// (e.g. "package-manager", "fingerprint", "filename").
	Method string

	// Confidence is a 0..1 score from the producing tool. Zero is
	// allowed and means "unspecified" rather than "0 % confidence".
	Confidence float64

	// Locations is the set of file locations where the component was
	// observed.
	Locations []EvidenceLocation
}

// EvidenceLocation is a single file path / line where evidence was found.
type EvidenceLocation struct {
	Path   string
	LineNo int
}

// IsZero reports whether the evidence has no useful content.
func (e Evidence) IsZero() bool {
	return e.Method == "" && e.Confidence == 0 && len(e.Locations) == 0
}
