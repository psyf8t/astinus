// Package cpe enriches Components that carry a PURL but no CPE 2.3
// identifier — the most common reason NVD-based vulnerability
// scanners produce false negatives.
//
// Stage 6 ships a hand-curated bootstrap mapping (~50 PURL → CPE
// entries for the most common open-source components) plus a
// heuristic fallback that constructs a best-effort CPE from the PURL
// shape. The full NVD CPE Dictionary loader lands in Stage 12
// (offline-db builder); the dictionary is too large to embed
// directly into the binary.
//
// # Property namespace
//
// The enricher does not invent new well-known properties beyond the
// ones declared in `internal/sbom/model/properties.go`. Multi-CPE
// round-trip already works via `astinus:cpe:N` (Stage 1 mapper).
// Per-component provenance is recorded as
// `astinus:cpe:source = bundled|heuristic` so consumers can tell
// which resolver produced the CPE.
package cpe

import (
	"fmt"
	"regexp"
	"strings"
)

// CPEv23 is one parsed CPE 2.3 identifier.
//
// CPE 2.3 has 11 attribute components after the prefix
// `cpe:2.3:<part>:`:
//
//	part : a (application) | o (operating-system) | h (hardware)
//	vendor / product / version / update / edition / language /
//	  sw_edition / target_sw / target_hw / other
//
// Each attribute is either a literal value or `*` (any) or `-` (NA).
type CPEv23 struct {
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SwEdition string
	TargetSw  string
	TargetHw  string
	Other     string
}

// String formats c as a canonical CPE 2.3 URI. Special characters in
// each attribute value (`:`, `+`, `@`, …) are backslash-escaped per
// NIST IR 7695 §6.1.2.5 — Debian-style versions like `1:2.75-10+b8`
// render as `1\:2.75-10\+b8`. Empty slots become the wildcard `*`.
// ADR-0058.
func (c CPEv23) String() string {
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		escapeOrPart(c.Part),
		EscapeCPE23Attribute(c.Vendor),
		EscapeCPE23Attribute(c.Product),
		EscapeCPE23Attribute(c.Version),
		EscapeCPE23Attribute(c.Update),
		EscapeCPE23Attribute(c.Edition),
		EscapeCPE23Attribute(c.Language),
		EscapeCPE23Attribute(c.SwEdition),
		EscapeCPE23Attribute(c.TargetSw),
		EscapeCPE23Attribute(c.TargetHw),
		EscapeCPE23Attribute(c.Other),
	)
}

// cpe23Regex is the structural check for the CPE 2.3 prefix + part
// fields. Slot validation is delegated to splitCPEv23 (which honours
// `\:` escapes per ADR-0058); the regex only confirms the prefix
// matches and the part attribute is one of `a` / `o` / `h` / `*`.
var cpe23Regex = regexp.MustCompile(`^cpe:2\.3:[aoh\*]:`)

// IsValidCPE reports whether s looks like a syntactically valid
// CPE 2.3 URI: correct prefix + part, and exactly 11 attribute slots
// once escaped colons are honoured.
func IsValidCPE(s string) bool {
	if !cpe23Regex.MatchString(s) {
		return false
	}
	_, ok := splitCPEv23(s)
	return ok
}

// Parse converts a CPE 2.3 URI into the structured form. Returns an
// error when the input does not match the canonical layout.
//
// Attribute values are unescaped before being returned, so callers
// see the human-readable form (`1:2.75-10+b8`, not `1\:2.75-10\+b8`).
// ADR-0058.
func Parse(s string) (CPEv23, error) {
	if !cpe23Regex.MatchString(s) {
		return CPEv23{}, fmt.Errorf("cpe: invalid 2.3 URI %q", s)
	}
	parts, ok := splitCPEv23(s)
	if !ok {
		return CPEv23{}, fmt.Errorf("cpe: invalid 2.3 URI %q", s)
	}
	// parts[0]="cpe", parts[1]="2.3", parts[2..12] = the 11 attributes.
	return CPEv23{
		Part:      parts[2],
		Vendor:    UnescapeCPE23Attribute(parts[3]),
		Product:   UnescapeCPE23Attribute(parts[4]),
		Version:   UnescapeCPE23Attribute(parts[5]),
		Update:    UnescapeCPE23Attribute(parts[6]),
		Edition:   UnescapeCPE23Attribute(parts[7]),
		Language:  UnescapeCPE23Attribute(parts[8]),
		SwEdition: UnescapeCPE23Attribute(parts[9]),
		TargetSw:  UnescapeCPE23Attribute(parts[10]),
		TargetHw:  UnescapeCPE23Attribute(parts[11]),
		Other:     UnescapeCPE23Attribute(parts[12]),
	}, nil
}

// Build returns a CPE 2.3 URI for an application component with the
// given vendor / product / version. All other attributes are `*`.
//
// vendor and product are lowercased; spaces and dots are preserved
// because real CPE entries (e.g. `apache_log_4j`) keep them. Special
// characters (`:`, `+`, `@`, etc.) are backslash-escaped per
// NIST IR 7695 §6.1.2.5 — pass `1:2.75-10+b8` as version, get back
// `cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:...`. Pass empty
// version to wildcard the slot. ADR-0058.
func Build(vendor, product, version string) string {
	c := CPEv23{
		Part:    "a",
		Vendor:  strings.ToLower(vendor),
		Product: strings.ToLower(product),
		Version: version,
	}
	return c.String()
}

// escapeOrPart projects the part field — it's the only slot where
// `*` is a structural part of the URI (parsed by the cpe23Regex
// directly) rather than a wildcard sentinel substitute for empty;
// empty input still maps to `*`, but we never escape the literal `*`.
func escapeOrPart(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
