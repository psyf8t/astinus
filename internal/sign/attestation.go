package sign

import "strings"

// attestationTypeFor maps an SBOM format string to the value
// `cosign attest --type` accepts. Cosign documents the canonical
// shorthand strings; an unknown format falls through to "custom",
// which makes cosign treat the predicate as opaque JSON (still
// valid, just not pretty-named in the attestation).
func attestationTypeFor(format string) string {
	switch normaliseFormat(format) {
	case "cyclonedx", "cyclonedx-json", "cyclonedx-xml":
		return "cyclonedx"
	case "spdx", "spdx-json", "spdx-tag-value":
		return "spdxjson"
	default:
		return "custom"
	}
}

// predicateURIFor returns the in-toto predicate type URI cosign
// stamps onto the attestation. Empty string for unknown formats
// (cosign still accepts the attestation; the URI is metadata, not
// a validation constraint).
func predicateURIFor(format string) string {
	switch normaliseFormat(format) {
	case "cyclonedx", "cyclonedx-json", "cyclonedx-xml":
		return "https://cyclonedx.org/bom/v1.6"
	case "spdx", "spdx-json", "spdx-tag-value":
		return "https://spdx.dev/Document"
	default:
		return ""
	}
}

// normaliseFormat lowercases + trims the format string so the
// attestation type / predicate URI lookups don't have to repeat
// the boilerplate.
func normaliseFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}
