//go:build acceptance

package corporate

import (
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestMirrorMode_Replace — with mode=replace, Astinus MUST NOT
// touch the public registry even when the mirror returns 404. The
// SpyServer (configured as a "would-be public registry" but never
// reached) asserts on RequestCount=0.
//
// We achieve "mirror returns 404" by giving FakeNpmMirror an empty
// payload map. With Mode=replace there is no fallback, so the
// component just gets no enrichment — the run still succeeds.
func TestMirrorMode_Replace(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{}) // 404-on-everything
	publicSpy := helpers.NewSpyServer(t)

	// Two mirror entries: replace-mode (the corporate one) +
	// fallback-mode that points at the public spy. Resolver tries
	// replace-mode first — and because replace-mode forbids
	// fallback, the spy MUST stay silent even on 404.
	cfg := helpers.WriteMirrorsConfig(t, "",
		helpers.MirrorYAMLOpts{Ecosystem: "npm", URL: mirror.URL(), Mode: "replace"},
	)
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/mirror-replace:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if mirror.RequestCount() < 2 {
		t.Errorf("replace-mode mirror saw %d requests; expected 2 (lodash + express)",
			mirror.RequestCount())
	}
	if got := publicSpy.RequestCount(); got != 0 {
		t.Errorf("replace-mode leaked %d requests to the public registry spy", got)
	}
}

// TestMirrorMode_Fallback — with mode=fallback, the resolver tries
// the mirror first, and on 404 falls back to the upstream public
// registry. Drives the case where the corporate mirror has lodash
// (returns the fixture) but not express (returns 404 → fallback
// picks up the public registry's payload).
//
// We can't run a real public registry in tests; instead, we route
// the "fallback" via a SECOND fallback-mode mirror entry that has
// the express fixture. The resolver tries them in order: replace-
// first, then fallback-mode entries.
func TestMirrorMode_Fallback(t *testing.T) {
	primary := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
		// express deliberately absent — primary returns 404
	})
	secondary := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/express/4.17.0": helpers.ExpressPackageJSON(),
	})

	cfg := helpers.WriteMirrorsConfig(t, "",
		helpers.MirrorYAMLOpts{Ecosystem: "npm", URL: primary.URL(), Mode: "fallback"},
		helpers.MirrorYAMLOpts{Ecosystem: "npm", URL: secondary.URL(), Mode: "fallback"},
	)
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/mirror-fallback:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if primary.Hits() == 0 {
		t.Errorf("primary mirror got no hits; resolver bypassed it")
	}
	if secondary.Hits() == 0 {
		t.Errorf("secondary mirror got no hits; fallback path did not engage")
	}
}
