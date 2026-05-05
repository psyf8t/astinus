package helpers

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Finding is a flattened view of one compliance finding stamped by
// the compliance enricher. Reconstructed from CycloneDX properties
// (the canonical model is post-render only).
type Finding struct {
	RuleID    string
	Severity  string
	Component string // bom-ref or component name; empty for SBOM-level
}

// GetNTIAFindings returns every NTIA-* finding stamped on the BOM.
// Includes SBOM-level findings (Metadata.Properties) and per-
// component findings (Component.Properties).
func GetNTIAFindings(bom *cdx.BOM) []Finding {
	return findingsByPrefix(bom, "NTIA-")
}

// GetEUCRAFindings returns every EUCRA-* finding.
func GetEUCRAFindings(bom *cdx.BOM) []Finding {
	return findingsByPrefix(bom, "EUCRA-")
}

// FilterBySeverity returns only the findings whose Severity (case-
// insensitive string match) equals want.
func FilterBySeverity(findings []Finding, want string) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if strings.EqualFold(f.Severity, want) {
			out = append(out, f)
		}
	}
	return out
}

// ComputeCPECoverage returns the fraction of Components that carry a
// non-empty CPE. Range [0, 1]; returns 0 for an empty BOM.
func ComputeCPECoverage(bom *cdx.BOM) float64 {
	if bom == nil || bom.Components == nil {
		return 0
	}
	total := 0
	with := 0
	for _, c := range *bom.Components {
		total++
		if c.CPE != "" {
			with++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(with) / float64(total)
}

// ComputePURLCoverage returns the fraction of Components that carry
// a PURL. Mirrors ComputeCPECoverage.
func ComputePURLCoverage(bom *cdx.BOM) float64 {
	if bom == nil || bom.Components == nil {
		return 0
	}
	total := 0
	with := 0
	for _, c := range *bom.Components {
		total++
		if c.PackageURL != "" {
			with++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(with) / float64(total)
}

// ComputeOriginCoverage returns the fraction of Components that have
// `astinus:origin` set on their property bag. The origin enricher
// stamps every component it touches; uncovered components are the
// ones the pipeline could not attribute.
func ComputeOriginCoverage(bom *cdx.BOM) float64 {
	if bom == nil || bom.Components == nil {
		return 0
	}
	total := 0
	with := 0
	for _, c := range *bom.Components {
		total++
		if propLookup(c.Properties, model.PropertyOrigin) != "" {
			with++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(with) / float64(total)
}

// GetRuntimeProperty returns the SBOM-level `astinus:runtime` value,
// or "" when unset.
func GetRuntimeProperty(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil {
		return ""
	}
	return propLookup(bom.Metadata.Properties, model.PropertyRuntime)
}

// GetAttributionConfidence returns the SBOM-level
// `astinus:attribution:confidence` value.
func GetAttributionConfidence(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil {
		return ""
	}
	return propLookup(bom.Metadata.Properties, model.PropertyAttributionConfidence)
}

// GetAttributionReason returns the SBOM-level
// `astinus:attribution:reason` value.
func GetAttributionReason(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil {
		return ""
	}
	return propLookup(bom.Metadata.Properties, model.PropertyAttributionReason)
}

// AnyPURLMatches reports whether any component's PURL satisfies pred.
// Tolerant to nil/empty BOMs.
func AnyPURLMatches(bom *cdx.BOM, pred func(string) bool) bool {
	if bom == nil || bom.Components == nil {
		return false
	}
	for _, c := range *bom.Components {
		if c.PackageURL != "" && pred(c.PackageURL) {
			return true
		}
	}
	return false
}

// ComponentCount returns len(*bom.Components) tolerant to nil.
func ComponentCount(bom *cdx.BOM) int {
	if bom == nil || bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}

// CountDuplicates counts components sharing identical (Name, Version,
// PackageURL) triples — the dedup enricher's contract is that this
// returns 0 for an enriched SBOM.
func CountDuplicates(bom *cdx.BOM) int {
	if bom == nil || bom.Components == nil {
		return 0
	}
	seen := map[string]int{}
	for _, c := range *bom.Components {
		key := c.Name + "\x00" + c.Version + "\x00" + c.PackageURL
		seen[key]++
	}
	dup := 0
	for _, n := range seen {
		if n > 1 {
			dup += n - 1
		}
	}
	return dup
}

// HasComponent reports whether any Component's Name equals name.
func HasComponent(bom *cdx.BOM, name string) bool {
	return FindComponent(bom, name) != nil
}

// FindComponent returns the first Component whose Name matches
// (case-sensitive), or nil.
func FindComponent(bom *cdx.BOM, name string) *cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Name == name {
			return c
		}
	}
	return nil
}

// FindComponentByPath returns the first Component whose
// astinus:layer:added-by property contains path. Used for binary-
// detection assertions ("the /app binary made it into the BOM").
func FindComponentByPath(bom *cdx.BOM, path string) *cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if propLookup(c.Properties, model.PropertyLayerAddedBy) == path {
			return c
		}
		if c.Name == strings.TrimPrefix(path, "/") {
			return c
		}
	}
	return nil
}

// findingsByPrefix scans every property under sbom.Metadata and each
// component for `astinus:compliance:finding:<prefix>...` keys and
// returns flattened Finding records.
func findingsByPrefix(bom *cdx.BOM, prefix string) []Finding {
	if bom == nil {
		return nil
	}
	out := make([]Finding, 0)
	if bom.Metadata != nil {
		out = appendFindingsFromProps(out, deref(bom.Metadata.Properties), prefix, "")
	}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			out = appendFindingsFromProps(out, deref(c.Properties), prefix, componentRef(&c))
		}
	}
	return out
}

// appendFindingsFromProps extracts every astinus:compliance:finding:<rule>
// property from props whose <rule> starts with prefix and appends a
// Finding for each.
func appendFindingsFromProps(out []Finding, props []cdx.Property, prefix, component string) []Finding {
	const propPrefix = "astinus:compliance:finding:"
	for _, p := range props {
		rule, ok := strings.CutPrefix(p.Name, propPrefix)
		if !ok || !strings.HasPrefix(rule, prefix) {
			continue
		}
		out = append(out, Finding{RuleID: rule, Severity: p.Value, Component: component})
	}
	return out
}

// componentRef returns BOMRef when set, otherwise Name.
func componentRef(c *cdx.Component) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	return c.Name
}

// propLookup reads a property by name from a CycloneDX
// `*[]Property` slice. Tolerant to nil / empty.
func propLookup(props *[]cdx.Property, name string) string {
	for _, p := range deref(props) {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func deref(p *[]cdx.Property) []cdx.Property {
	if p == nil {
		return nil
	}
	return *p
}
