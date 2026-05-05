package transport

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// doGet performs a context-aware GET (so noctx is happy), closes the
// response body locally (so bodyclose is happy), and returns only the
// final transport error. Tests that need to inspect the status check
// the err == nil contract; tests that need to count hits do so via
// the server handler's side effects.
func doGet(t *testing.T, rt http.RoundTripper, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestNewSetsUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	rt, err := New(Options{MaxRetries: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := doGet(t, rt, srv.URL); err != nil {
		t.Fatalf("doGet: %v", err)
	}

	if !strings.HasPrefix(got, "astinus/") {
		t.Errorf("User-Agent = %q, want prefix astinus/", got)
	}
	if !strings.Contains(got, "https://github.com/psyf8t/astinus") {
		t.Errorf("User-Agent = %q, want repo URL", got)
	}
}

func TestRetryAttempts5xx(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rt, err := New(Options{MaxRetries: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = doGet(t, rt, srv.URL)
	if hits != 3 {
		t.Errorf("hit count = %d, want 3 (initial + 2 retries)", hits)
	}
}

func TestExplicitProxyURLOverridesEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://env-proxy:9999")
	rt, err := New(Options{MaxRetries: -1, Proxy: "http://explicit-proxy:8080"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	uat, ok := rt.(*userAgentTransport)
	if !ok {
		t.Fatalf("rt = %T, want *userAgentTransport", rt)
	}
	tr, ok := uat.base.(*http.Transport)
	if !ok {
		t.Fatalf("uat.base = %T, want *http.Transport", uat.base)
	}
	got, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if got == nil || got.Host != "explicit-proxy:8080" {
		t.Errorf("proxy URL = %v, want explicit-proxy:8080", got)
	}
}

func TestNewRejectsBadProxy(t *testing.T) {
	_, err := New(Options{Proxy: "://no-scheme"})
	if err == nil {
		t.Fatal("expected error for malformed proxy")
	}
}

func TestCustomCABundleAccepted(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := os.WriteFile(caPath, encodeCert(srv.Certificate()), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	rt, err := New(Options{CABundle: caPath, MaxRetries: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := doGet(t, rt, srv.URL); err != nil {
		t.Fatalf("Get with custom CA: %v", err)
	}
}

func TestCustomCABundleRejectsMissingFile(t *testing.T) {
	_, err := New(Options{CABundle: "/no/such/ca/bundle.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA bundle path")
	}
	if !strings.Contains(err.Error(), "/no/such/ca/bundle.pem") {
		t.Errorf("error = %v, expected to mention path", err)
	}
}

func TestCustomCABundleRejectsNonPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-pem.pem")
	if err := os.WriteFile(bad, []byte("hello, not a cert"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := New(Options{CABundle: bad})
	if err == nil {
		t.Fatal("expected error for non-PEM CA bundle")
	}
}

func TestSkipTLSVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt1, err := New(Options{MaxRetries: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := doGet(t, rt1, srv.URL); err == nil {
		t.Fatal("expected TLS verification to fail without CA bundle")
	}

	rt2, err := New(Options{SkipTLSVerify: true, MaxRetries: -1})
	if err != nil {
		t.Fatalf("New skip-verify: %v", err)
	}
	if err := doGet(t, rt2, srv.URL); err != nil {
		t.Fatalf("Get with skip-verify: %v", err)
	}
}

func TestLoadCAPoolEmptyPathReturnsSystem(t *testing.T) {
	pool, err := loadCAPool("")
	if err != nil {
		t.Fatalf("loadCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool for empty path")
	}
}

// encodeCert returns the PEM-encoded form of cert.
func encodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
