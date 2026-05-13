//go:build acceptance

package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// WriteCDXSBOM serialises a minimal CycloneDX SBOM with the supplied
// components and tools, and returns the on-disk path. Sprint 4
// acceptance tests use this to drive specific input shapes through
// the astinus binary (golang-only SBOM for the Task 3 CPE policy
// test, trivy-tool-stamped SBOM for the Task 5 source-detection
// log, etc.). S4 Task 7.
func WriteCDXSBOM(tb testing.TB, components []cdx.Component, tools ...cdx.Tool) string {
	tb.Helper()
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_5,
		SerialNumber: "urn:uuid:sprint4-acceptance",
		Version:      1,
		Metadata: &cdx.Metadata{
			Tools: &cdx.ToolsChoice{Tools: &tools},
		},
		Components: &components,
	}
	dir := tb.TempDir()
	path := filepath.Join(dir, "input.cdx.json")
	body, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		tb.Fatalf("MarshalIndent BOM: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		tb.Fatalf("WriteFile %s: %v", path, err)
	}
	return path
}

// FindComponent walks the BOM's component tree and returns the
// first entry whose Name + PURL match. Returns nil when no match.
// Sprint 4 tests use this to assert per-component property stamps
// without writing the tree traversal in every test.
func FindComponent(bom *cdx.BOM, name, purl string) *cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	return findIn(*bom.Components, name, purl)
}

func findIn(comps []cdx.Component, name, purl string) *cdx.Component {
	for i := range comps {
		c := &comps[i]
		if c.Name == name && (purl == "" || c.PackageURL == purl) {
			return c
		}
		if c.Components != nil {
			if found := findIn(*c.Components, name, purl); found != nil {
				return found
			}
		}
	}
	return nil
}

// PropertyValue returns the value of the named property on c, or
// the empty string when the property isn't set. Mirrors the
// model.PropertyMap shape exposed by the Astinus writer for any
// foreign-format consumer.
func PropertyValue(c *cdx.Component, name string) string {
	if c == nil || c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// MetadataProperty returns the value of an SBOM-level metadata
// property, or "" when absent. Sprint 4 stamps several such keys
// (`astinus:cpe:mode`, `astinus:cpe:sources-skipped`,
// `astinus:basediff:detection-method`, …) so the acceptance suite
// reads them via this helper.
func MetadataProperty(bom *cdx.BOM, name string) string {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil {
		return ""
	}
	for _, p := range *bom.Metadata.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
