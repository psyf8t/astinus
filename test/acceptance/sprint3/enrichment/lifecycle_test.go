//go:build acceptance

package enrichment

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestLifecycleEnricher_StampsBundledSnapshot — with --no-network,
// the lifecycle enricher MUST still annotate components when their
// product is in the bundled endoflife snapshot. This is the
// air-gapped happy path: customer runs Astinus offline, and Node /
// Python / Debian get EOL state from the embedded JSON.
//
// Asserts on the components in MinimalRuntimeSBOM:
//
//   - node 20.18.0 → cycle "20", LTS, supported (status active or maintenance)
//   - python 3.8.20 → cycle "3.8", EOL since 2024-10-01 → status "eol"
//   - debian 10 → cycle "10", EOL since 2024-06-30 → status "eol"
func TestLifecycleEnricher_StampsBundledSnapshot(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalRuntimeSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/lifecycle:1.0",
		NoNetwork: true,
		Extra:     []string{"--disable", "layer", "--disable", "evidence"},
	})

	for _, name := range []string{"node", "python", "debian"} {
		c := findComponent(t, res.BOM, name)
		if !hasProperty(c, "astinus:lifecycle:source", "bundled") {
			t.Errorf("%s: missing astinus:lifecycle:source=bundled; properties=%+v",
				name, c.Properties)
		}
		if propertyValue(c, "astinus:lifecycle:status") == "" {
			t.Errorf("%s: missing astinus:lifecycle:status", name)
		}
	}

	pyStatus := propertyValue(findComponent(t, res.BOM, "python"), "astinus:lifecycle:status")
	if pyStatus != "eol" {
		t.Errorf("python 3.8.20: expected lifecycle status=eol, got %q", pyStatus)
	}

	debStatus := propertyValue(findComponent(t, res.BOM, "debian"), "astinus:lifecycle:status")
	if debStatus != "eol" {
		t.Errorf("debian 10: expected lifecycle status=eol, got %q", debStatus)
	}
}

// TestLifecycleEnricher_DisabledFlag — `--no-lifecycle` should skip
// the enricher even when the SBOM has well-known runtime
// components. The output BOM should have NO astinus:lifecycle:*
// properties.
func TestLifecycleEnricher_DisabledFlag(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalRuntimeSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:        sbom,
		Image:       "test/no-lifecycle:1.0",
		NoLifecycle: true,
		Extra:       []string{"--disable", "layer", "--disable", "evidence"},
	})

	for _, name := range []string{"node", "python", "debian"} {
		c := findComponent(t, res.BOM, name)
		if propertyValue(c, "astinus:lifecycle:status") != "" {
			t.Errorf("%s: --no-lifecycle leaked astinus:lifecycle:status into output",
				name)
		}
	}
}

// propertyValue returns the value for the named property, or "" if
// absent. Tests that only care "is it set?" can compare to "" to
// detect absence.
func propertyValue(c *cdx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
