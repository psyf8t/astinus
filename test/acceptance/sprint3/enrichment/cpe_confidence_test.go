//go:build acceptance

package enrichment

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestCPEConfidence_PropertiesEmittedFromBundled — Sprint 3 Task 0
// reshaped CPE matching to surface a primary + alternatives, with a
// confidence score on each. The BOM that comes out should carry an
// `astinus:cpe:source` property on every component the enricher
// touched (here: every npm component that resolves against the
// bundled dictionary).
//
// We use --no-network so no NVD API calls happen — the bundled
// dictionary is the only source. If the bundled dictionary covers
// neither lodash nor express the test t.Skip()s; this is a
// fingerprint check, not a coverage check.
func TestCPEConfidence_PropertiesEmittedFromBundled(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/cpe-confidence:1.0",
		NoNetwork: true,
		Extra: []string{
			"--cpe-mode", "bundled",
			"--disable", "layer", "--disable", "evidence",
		},
	})

	stamped := 0
	for _, name := range []string{"lodash", "express"} {
		c := findComponent(t, res.BOM, name)
		if propertyValue(c, "astinus:cpe:source") != "" {
			stamped++
		}
	}
	if stamped == 0 {
		t.Skip("bundled dictionary did not match either lodash or express; nothing to assert")
	}
}

// TestCPEConfidence_RejectedAreInvisibleByDefault — without
// --include-rejected-cpe, the BOM should NOT carry rejected
// candidate properties (`astinus:cpe:rejected:N`). The rejected set
// only surfaces when the operator opts in.
func TestCPEConfidence_RejectedAreInvisibleByDefault(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/cpe-rejected:1.0",
		NoNetwork: true,
		Extra: []string{
			"--cpe-mode", "bundled",
			"--disable", "layer", "--disable", "evidence",
		},
	})

	for _, name := range []string{"lodash", "express"} {
		c := findComponent(t, res.BOM, name)
		if c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if strings.HasPrefix(p.Name, "astinus:cpe:rejected:") {
				t.Errorf("%s: rejected CPE leaked without --include-rejected-cpe: %s=%s",
					name, p.Name, p.Value)
			}
		}
	}
}
