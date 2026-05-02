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

// String formats c as a canonical CPE 2.3 URI.
func (c CPEv23) String() string {
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		orStar(c.Part),
		orStar(c.Vendor),
		orStar(c.Product),
		orStar(c.Version),
		orStar(c.Update),
		orStar(c.Edition),
		orStar(c.Language),
		orStar(c.SwEdition),
		orStar(c.TargetSw),
		orStar(c.TargetHw),
		orStar(c.Other),
	)
}

// cpe23Regex is a relaxed CPE 2.3 validator. It enforces the prefix
// + part + the 10 attribute slots; we leave the deeper character set
// rules (CPE allows escaped colons via `\:`) to libraries that need
// strict NVD-grade validation. For SBOM enrichment, "shape is right"
// is enough.
var cpe23Regex = regexp.MustCompile(
	`^cpe:2\.3:[aoh\*]:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$`,
)

// IsValidCPE reports whether s looks like a syntactically valid
// CPE 2.3 URI.
func IsValidCPE(s string) bool { return cpe23Regex.MatchString(s) }

// Parse converts a CPE 2.3 URI into the structured form. Returns an
// error when the input does not match the canonical layout.
func Parse(s string) (CPEv23, error) {
	if !IsValidCPE(s) {
		return CPEv23{}, fmt.Errorf("cpe: invalid 2.3 URI %q", s)
	}
	parts := strings.SplitN(s, ":", 13)
	// parts[0]="cpe", parts[1]="2.3", parts[2..12] = the 11 attributes.
	return CPEv23{
		Part:      parts[2],
		Vendor:    parts[3],
		Product:   parts[4],
		Version:   parts[5],
		Update:    parts[6],
		Edition:   parts[7],
		Language:  parts[8],
		SwEdition: parts[9],
		TargetSw:  parts[10],
		TargetHw:  parts[11],
		Other:     parts[12],
	}, nil
}

// Build returns a CPE 2.3 URI for an application component with the
// given vendor / product / version. All other attributes are `*`.
//
// vendor and product are lowercased; spaces and dots are not touched
// because real CPE entries (e.g. `apache_log_4j`) preserve them.
// Pass empty version to get a wildcard match across all versions.
func Build(vendor, product, version string) string {
	c := CPEv23{
		Part:    "a",
		Vendor:  strings.ToLower(vendor),
		Product: strings.ToLower(product),
		Version: orStar(version),
	}
	return c.String()
}

// orStar returns s when non-empty, otherwise the CPE wildcard "*".
func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
