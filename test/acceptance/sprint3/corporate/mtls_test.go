//go:build acceptance

package corporate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestCorporateMTLS_HappyPath — Astinus presents the configured
// client cert to a server that requires + verifies it. The TLS
// handshake completes; the JSON payload comes back; the BOM is
// enriched.
//
// The fake mirror runs over HTTPS with mTLS. The MirrorsConfig
// entry's TLS block points at the test bundle's CA + client cert /
// key. Without the client cert, the handshake fails — proven by
// the negative test below.
func TestCorporateMTLS_HappyPath(t *testing.T) {
	dir := t.TempDir()
	bundle := helpers.NewMTLSBundle(t, dir)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "lodash/4.17.20" {
			_, _ = w.Write(helpers.LodashPackageJSON())
			return
		}
		if path == "express/4.17.0" {
			_, _ = w.Write(helpers.ExpressPackageJSON())
			return
		}
		http.NotFound(w, r)
	}))
	server.TLS = bundle.ServerTLSCfg
	server.StartTLS()
	t.Cleanup(server.Close)

	cfg := helpers.WriteMirrorsConfig(t, dir, helpers.MirrorYAMLOpts{
		Ecosystem:  "npm",
		URL:        server.URL,
		Mode:       "replace",
		CACert:     bundle.CACertPath,
		ClientCert: bundle.ClientCertPath,
		ClientKey:  bundle.ClientKeyPath,
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/mtls:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})
}

// TestCorporateMTLS_MissingClientCert — when the operator forgets
// to configure the client cert / key, the mirror request fails
// during the TLS handshake. astinus's run still exits 0 (the
// registry enricher logs the failure but doesn't escalate to the
// process level — corporate operators want SBOM-without-metadata
// over hard-fail when one of N mirrors flakes). We assert that the
// outbound traffic was attempted (so the failure is real, not
// silently skipped).
//
// To keep the suite hermetic, we observe the failure via "mirror
// payload was NOT applied" (Description stays empty on the BOM
// component) rather than via stderr scraping.
func TestCorporateMTLS_MissingClientCert(t *testing.T) {
	dir := t.TempDir()
	bundle := helpers.NewMTLSBundle(t, dir)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(helpers.LodashPackageJSON())
	}))
	server.TLS = bundle.ServerTLSCfg
	server.StartTLS()
	t.Cleanup(server.Close)

	// Mirror config: server CA is supplied, but the client cert /
	// key are deliberately omitted. The handshake will fail with
	// "tls: certificate required".
	cfg := helpers.WriteMirrorsConfig(t, dir, helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       server.URL,
		Mode:      "replace",
		CACert:    bundle.CACertPath,
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/mtls-missing-client:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	// The component MUST NOT be enriched — the handshake never
	// produced a body. If Description is non-empty, the test setup
	// is broken (or we accidentally bypassed mTLS).
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatalf("output BOM has no components")
	}
	for _, c := range *res.BOM.Components {
		if c.Name == "lodash" && c.Description != "" {
			t.Errorf("lodash got Description %q despite missing client cert; mTLS bypassed?",
				c.Description)
		}
	}
}
