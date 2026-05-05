//go:build acceptance

package corporate

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestCorporateProxy_Authorization — when the operator runs astinus
// behind a corporate HTTP_PROXY that requires Basic auth, the
// outbound npm-mirror requests MUST traverse the proxy and the
// proxy MUST see the credentials embedded in the proxy URL.
//
// Scenario: SBOM with two npm components, FakeNpmMirror configured
// as the upstream, FakeProxy in front of it with HTTPS_PROXY +
// HTTP_PROXY pointing at it. Astinus's transport layer reads
// HTTPS_PROXY/HTTP_PROXY via http.ProxyFromEnvironment.
//
// KNOWN LIMITATION: Go's http.ProxyFromEnvironment hardcodes a
// loopback bypass — requests to 127.0.0.1 / ::1 / localhost SKIP
// the proxy regardless of HTTP_PROXY. Since httptest.Server binds
// to 127.0.0.1, this in-process test cannot drive the proxy code
// path. The behaviour is verified at the unit level in
// `internal/enrich/registry/transport_test.go` and end-to-end in
// the corporate-acceptance environment (real proxy + non-localhost
// mirror) — see docs/private/sprint3-acceptance-results.md.
func TestCorporateProxy_Authorization(t *testing.T) {
	t.Skip("Go's ProxyFromEnvironment bypasses localhost; see test comment for full coverage notes")
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
		"/express/4.17.0": helpers.ExpressPackageJSON(),
	})
	proxy := helpers.NewFakeProxy(t, mirror.Server())

	// Inject credentials via proxy URL — http.ProxyFromEnvironment
	// passes them as Proxy-Authorization automatically.
	proxyURL := strings.Replace(proxy.URL(), "http://", "http://corp:secret@", 1)
	helpers.SetEnv(t, "HTTP_PROXY", proxyURL)
	helpers.SetEnv(t, "HTTPS_PROXY", proxyURL)
	helpers.UnsetEnv(t, "NO_PROXY")
	helpers.UnsetEnv(t, "no_proxy")

	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       mirror.URL(),
		Mode:      "replace",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/proxy:1.0",
		MirrorsConfig: cfg,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if got := proxy.RequestCount(); got == 0 {
		t.Fatalf("proxy saw no requests; HTTP_PROXY/HTTPS_PROXY env vars were not honoured")
	}
	auth := proxy.LastAuthHeader()
	if auth == "" {
		t.Errorf("proxy did not receive Proxy-Authorization header (creds embedded in URL not propagated)")
	}
}

// TestCorporateProxy_NoLeakWithNoNetwork — when --no-network is set,
// astinus MUST NOT call out at all, even if the proxy is configured
// in env vars. This is the air-gapped customer's safety net: a
// stray HTTPS_PROXY left in the host env can't smuggle traffic
// through.
func TestCorporateProxy_NoLeakWithNoNetwork(t *testing.T) {
	mirror := helpers.NewFakeNpmMirror(t, map[string][]byte{
		"/lodash/4.17.20": helpers.LodashPackageJSON(),
	})
	proxy := helpers.NewFakeProxy(t, mirror.Server())
	helpers.SetEnv(t, "HTTP_PROXY", proxy.URL())
	helpers.SetEnv(t, "HTTPS_PROXY", proxy.URL())

	cfg := helpers.WriteMirrorsConfig(t, "", helpers.MirrorYAMLOpts{
		Ecosystem: "npm",
		URL:       mirror.URL(),
		Mode:      "replace",
	})
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:          sbom,
		Image:         "test/proxy-no-net:1.0",
		MirrorsConfig: cfg,
		NoNetwork:     true,
		Extra:         []string{"--disable", "layer", "--disable", "evidence"},
	})

	if got := proxy.RequestCount(); got != 0 {
		t.Errorf("--no-network leaked %d requests through the proxy", got)
	}
	if got := mirror.RequestCount(); got != 0 {
		t.Errorf("--no-network leaked %d direct requests to the mirror", got)
	}
}
