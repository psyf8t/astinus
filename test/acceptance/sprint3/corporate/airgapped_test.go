//go:build acceptance

package corporate

import (
	"net/http"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestAirGapped_NoNetworkAndNoMirror — air-gapped customer with
// `--no-network` and no mirrors-config. The run MUST succeed
// (registry enrichment falls through to "no source available"),
// the lifecycle enricher MUST still annotate from the bundled
// snapshot, and the output BOM MUST be valid.
//
// This is the pessimistic baseline — no internet, no corporate
// mirror — and we still produce a useful SBOM.
func TestAirGapped_NoNetworkAndNoMirror(t *testing.T) {
	helpers.UnsetEnv(t, "HTTP_PROXY")
	helpers.UnsetEnv(t, "HTTPS_PROXY")
	helpers.UnsetEnv(t, "http_proxy")
	helpers.UnsetEnv(t, "https_proxy")

	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalRuntimeSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/airgapped:1.0",
		NoNetwork: true,
		Extra:     []string{"--disable", "layer", "--disable", "evidence"},
	})

	if res.BOM == nil || res.BOM.Components == nil || len(*res.BOM.Components) == 0 {
		t.Fatalf("air-gapped run produced empty BOM")
	}

	// Every component should still have lifecycle properties from
	// the bundled snapshot — that's the air-gapped guarantee.
	for _, c := range *res.BOM.Components {
		if c.Properties == nil {
			t.Errorf("%s: no properties at all in air-gapped output", c.Name)
			continue
		}
		var sawLifecycle bool
		for _, p := range *c.Properties {
			if p.Name == "astinus:lifecycle:source" && p.Value == "bundled" {
				sawLifecycle = true
				break
			}
		}
		if !sawLifecycle {
			t.Errorf("%s: missing astinus:lifecycle:source=bundled in air-gapped run",
				c.Name)
		}
	}
}

// TestAirGapped_BearerTokenFromEnv — the air-gapped customer
// uploads their internal Artifactory creds via env var; the
// mirrors-config references the env var via `token_env`. The
// FakeNpmMirror's authFunc validates the Authorization header.
func TestAirGapped_BearerTokenFromEnv(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
		"/express/4.17.0": helpers.ExpressPackageJSON(),
	})
	const wantToken = "Bearer hunter2-secret"
	mirror.SetAuthFunc(func(r *http.Request) bool {
		return r.Header.Get("Authorization") == wantToken
	})

	helpers.SetEnv(t, "TEST_NPM_TOKEN", "hunter2-secret")

	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem:      "npm",
		URL:            mirror.URL(),
		Mode:           "replace",
		BearerTokenEnv: "TEST_NPM_TOKEN",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/airgapped-auth:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if mirror.Hits() < 2 {
		t.Errorf("auth-gated mirror: only %d hits — bearer token did not authenticate",
			mirror.Hits())
	}
}
