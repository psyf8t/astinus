package model

// Format is the wire format an SBOM was read from or should be written to.
type Format string

// Recognized SBOM wire formats.
const (
	// FormatCycloneDXJSON is CycloneDX in JSON encoding (the default).
	FormatCycloneDXJSON Format = "cyclonedx-json"
	// FormatCycloneDXXML is CycloneDX in XML encoding.
	FormatCycloneDXXML Format = "cyclonedx-xml"
	// FormatSPDXJSON is SPDX in JSON encoding.
	FormatSPDXJSON Format = "spdx-json"
	// FormatSPDXTagValue is SPDX tag-value encoding.
	FormatSPDXTagValue Format = "spdx-tag-value"
	// FormatUnknown is the sentinel for unrecognized input.
	FormatUnknown Format = "unknown"
)

// IsCycloneDX reports whether f is one of the CycloneDX encodings.
func (f Format) IsCycloneDX() bool {
	return f == FormatCycloneDXJSON || f == FormatCycloneDXXML
}

// IsSPDX reports whether f is one of the SPDX encodings.
func (f Format) IsSPDX() bool {
	return f == FormatSPDXJSON || f == FormatSPDXTagValue
}
