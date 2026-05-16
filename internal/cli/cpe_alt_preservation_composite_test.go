package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
)

// TestAltCPEPreservation_CompositePipelineOnSslClientCVE is the
// Sprint 9 Task 2 "real-image proxy" pin. Drives a real CDX 1.5
// JSON fragment carrying 5 duplicate `syft:cpe23` Property
// entries on a single busybox-applet component through the
// production pipeline:
//
//	cyclonedx.ReadJSON  →  cpe.New().Enrich  →  output Component
//
// And asserts that every one of Syft's 5 alt-CPE variants
// (busybox/busybox, busybox/ssl_client, busybox/ssl-client,
// ssl_client/ssl_client, ssl-client/ssl-client) survives into
// the output across primary `c.CPEs[0]` + alternative
// `c.Properties[astinus:cpe:alternative:N]` slots combined.
//
// This is the unit-faithful proxy for the C-nginx CVE-2025-60876
// Grype-binary recovery: a regression that re-collapses Syft's
// duplicate `syft:cpe23` properties to a single output CPE fails
// this test immediately and the CVE would silently disappear in
// production.
//
// S9 Task 2 / ADR-0062 amendment.
func TestAltCPEPreservation_CompositePipelineOnSslClientCVE(t *testing.T) {
	// CDX 1.5 fragment hand-crafted to mirror the Syft output
	// shape for busybox-applet ssl_client. Five duplicate
	// `syft:cpe23` Property entries — the failure-shape input that
	// pre-S6-T5's `map[string]string` collapse mishandled.
	const cdxFragment = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:apk/alpine/ssl_client@1.37.0-r30",
      "name": "ssl_client",
      "version": "1.37.0-r30",
      "purl": "pkg:apk/alpine/ssl_client@1.37.0-r30",
      "properties": [
        { "name": "syft:cpe23", "value": "cpe:2.3:a:busybox:busybox:1.37.0-r30:*:*:*:*:*:*:*" },
        { "name": "syft:cpe23", "value": "cpe:2.3:a:busybox:ssl_client:1.37.0-r30:*:*:*:*:*:*:*" },
        { "name": "syft:cpe23", "value": "cpe:2.3:a:busybox:ssl-client:1.37.0-r30:*:*:*:*:*:*:*" },
        { "name": "syft:cpe23", "value": "cpe:2.3:a:ssl_client:ssl_client:1.37.0-r30:*:*:*:*:*:*:*" },
        { "name": "syft:cpe23", "value": "cpe:2.3:a:ssl-client:ssl-client:1.37.0-r30:*:*:*:*:*:*:*" }
      ]
    }
  ]
}`

	sbom, err := cyclonedx.ReadJSON(strings.NewReader(cdxFragment))
	if err != nil {
		t.Fatalf("cyclonedx.ReadJSON: %v", err)
	}
	if got, want := len(sbom.Components), 1; got != want {
		t.Fatalf("got %d components, want %d", got, want)
	}

	// Ingest must already preserve all 5 syft:cpe23 entries as
	// distinct CPEs on the model (S6-T5's `appendSyftCPEs`).
	if got := len(sbom.Components[0].CPEs); got < 5 {
		t.Fatalf("post-read CPEs = %d, want ≥ 5 — appendSyftCPEs failed to preserve duplicates",
			got)
	}

	enricher := cpe.New().WithTotalCap(0)
	if err := enricher.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	out := sbom.Components[0]

	// Collect every CPE the operator-facing output exposes:
	// primary + alternatives (the union Grype consumes per
	// component).
	visible := make([]string, 0, len(out.CPEs)+5)
	visible = append(visible, out.CPEs...)
	for k, v := range out.Properties {
		if strings.HasPrefix(k, "astinus:cpe:alternative:") &&
			!strings.Contains(k, ":source") &&
			!strings.Contains(k, ":confidence") {
			visible = append(visible, v)
		}
	}

	// CVE-2025-60876 keys on one of the busybox/ssl_client*
	// shapes. Each of the 5 fragment shapes must survive — that's
	// the contract Sprint 9 README's reproducer asserts at the
	// Grype-binary level.
	wantFragments := []string{
		":busybox:busybox:",
		":busybox:ssl_client:",
		":busybox:ssl-client:",
		":ssl_client:ssl_client:",
		":ssl-client:ssl-client:",
	}
	for _, frag := range wantFragments {
		if !anyContains(visible, frag) {
			t.Errorf("post-enrich CPE set missing vendor/product fragment %q\nvisible CPEs: %v",
				frag, visible)
		}
	}

	// Pre-cap count records the classifier's view of the alt set
	// (10 is the cap; here the candidate slate should land inside
	// the cap).
	if got := out.Properties["astinus:cpe:alternatives-count"]; got == "" {
		t.Errorf("astinus:cpe:alternatives-count missing — S6-T5 stamp should be present")
	}
}

func anyContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
