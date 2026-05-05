//go:build acceptance

package enrichment

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestRegistryEnricher_PopulatesMetadata is the happy-path
// acceptance: an SBOM with two npm components (lodash, express) + a
// FakeNpmMirror configured as the npm replace-mode mirror should
// emerge from `astinus enrich` with description / license /
// homepage filled in from the mirror payloads.
func TestRegistryEnricher_PopulatesMetadata(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
		"/express/4.17.0": helpers.ExpressPackageJSON(),
	})

	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       mirror.URL(),
		Mode:      "replace",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/registry-enrich:1.0",
		MirrorsConfig: cfg,
		// Image isn't a real container — disable the enrichers that
		// would otherwise touch the registry.
		Extra: []string{"--disable", "layer", "--disable", "evidence"},
	})

	lodash := findComponent(t, res.BOM, "lodash")
	if lodash.Description == "" {
		t.Errorf("lodash: registry enricher did not populate Description")
	}
	if !hasLicenseID(lodash, "MIT") {
		t.Errorf("lodash: registry enricher did not populate Licenses (MIT expected); got %+v", lodash.Licenses)
	}
	if !hasProperty(lodash, "astinus:registry:source", "npm") {
		t.Errorf("lodash: missing astinus:registry:source=npm; got %+v", lodash.Properties)
	}

	if mirror.RequestCount() < 2 {
		t.Errorf("mirror saw only %d requests; expected 2 (lodash + express)", mirror.RequestCount())
	}
	if mirror.Misses() != 0 {
		t.Errorf("mirror reported %d misses; expected 0 — fixture map covers both packages",
			mirror.Misses())
	}
}

// TestRegistryEnricher_NoNetworkSkipsEnrichment — when the operator
// passes --no-network, the registry enricher MUST NOT fire even if
// a mirrors-config is present. The mirror's RequestCount stays 0.
func TestRegistryEnricher_NoNetworkSkipsEnrichment(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
	})
	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       mirror.URL(),
		Mode:      "replace",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/no-network:1.0",
		MirrorsConfig: cfg,
		NoNetwork:     true,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if got := mirror.RequestCount(); got != 0 {
		t.Errorf("--no-network leaked %d requests to the mirror", got)
	}
}

// TestRegistryEnricher_DisabledFlag — `--no-registry` must keep the
// mirror untouched even with a happy mirrors-config in scope. Used
// by air-gapped customers who explicitly want the enricher off.
func TestRegistryEnricher_DisabledFlag(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
	})
	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       mirror.URL(),
		Mode:      "replace",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/no-registry:1.0",
		MirrorsConfig: cfg,
		NoRegistry:    true,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if got := mirror.RequestCount(); got != 0 {
		t.Errorf("--no-registry leaked %d requests to the mirror", got)
	}
}

// ─── helpers ──────────────────────────────────────────────────────

// findComponent returns the BOM component whose Name matches name,
// or t.Fatals if absent. Tests look up by Name (not BOMRef) because
// the BOMRef may have been mutated by enrichers (synthesised refs).
func findComponent(t *testing.T, bom *cdx.BOM, name string) *cdx.Component {
	t.Helper()
	if bom == nil || bom.Components == nil {
		t.Fatalf("bom has no components")
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %q not found in BOM (%d components present)", name, len(*bom.Components))
	return nil
}

// hasProperty checks the Component's Properties for the given
// name=value pair. Wildcards aren't supported; "value" matches
// verbatim. For "name with optional value" semantics, pass an empty
// value substring with hasPropertyContains.
func hasProperty(c *cdx.Component, name, value string) bool {
	if c.Properties == nil {
		return false
	}
	for _, p := range *c.Properties {
		if p.Name == name && (value == "" || p.Value == value) {
			return true
		}
	}
	return false
}

// hasLicenseID returns true when c.Licenses includes id (exact
// SPDX-id match). Express's payload omits the SPDX `license` field
// in our fixture, so callers should only assert on lodash.
func hasLicenseID(c *cdx.Component, id string) bool {
	if c.Licenses == nil {
		return false
	}
	for _, lc := range *c.Licenses {
		if lc.License != nil && strings.EqualFold(lc.License.ID, id) {
			return true
		}
		if strings.EqualFold(lc.Expression, id) {
			return true
		}
	}
	return false
}
