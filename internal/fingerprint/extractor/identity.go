package extractor

// Identity is the parsed package identity an Extractor recovers
// from a binary / archive.
//
// Empty Identity (no Name, no PURL, no CPE) means "this extractor
// matched the file shape but couldn't recover usable metadata"; the
// caller should treat it as a no-op rather than a failure.
type Identity struct {
	// Name is the package name. Required for the identity to be
	// considered non-empty.
	Name string

	// Version is the package version. Optional — some
	// fingerprints (a Go binary built with -trimpath, an ELF
	// library with no SONAME version suffix) yield Name without
	// Version.
	Version string

	// PURL is the Package URL the extractor's ecosystem natively
	// maps to. Empty when the extractor could not synthesise one
	// (typically because Name was empty).
	PURL string

	// CPE is reserved for future ecosystems whose metadata
	// directly carries CPE — none today; the CPE enricher
	// resolves CPE from PURL downstream.
	CPE string

	// Vendor is the supplier name when the metadata records one
	// (PE VERSIONINFO's CompanyName, JAR Implementation-Vendor,
	// Python Author).
	Vendor string

	// SubComponents are nested packages embedded in the same file.
	// Go binaries expose the full module graph; Rust binaries
	// (when built with `cargo auditable`) expose every linked
	// crate. Surfaced so the SBOM gets the full dependency tree
	// from a single binary scan.
	SubComponents []Identity

	// Properties is the bag of extractor-specific key/value
	// breadcrumbs (Go GoVersion, ELF SONAME, JAR Main-Class).
	// Caller copies relevant entries onto Component.Properties.
	Properties map[string]string

	// Source records which extractor produced the identity; the
	// Registry stamps it before returning so callers can sort
	// across extractors. Operators consume this through the
	// `astinus:extractor:source` Component property the untracked
	// enricher writes.
	Source string

	// Confidence mirrors the producing extractor's Confidence().
	// 1.0 = exact metadata; < 1.0 = heuristic. The Registry sorts
	// matches by this field.
	Confidence float64
}

// IsEmpty reports whether the identity has nothing usable. Used by
// the Registry to drop the no-match-no-error case.
func (i Identity) IsEmpty() bool {
	return i.Name == "" && i.PURL == "" && i.CPE == ""
}
