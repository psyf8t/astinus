package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psyf8t/astinus/internal/config"
)

// TestMirrorChain_ReplaceModeExcludesUpstream — the security
// default for air-gapped environments: a replace-mode mirror means
// upstream is NEVER tried, even when the mirror returns 404.
func TestMirrorChain_ReplaceModeExcludesUpstream(t *testing.T) {
	chain := MirrorChain{
		Mirrors: []config.MirrorEntry{
			{URL: "https://mirror.corp", Mode: config.MirrorModeReplace},
		},
		Upstream: "https://upstream.example",
	}
	endpoints := chain.Endpoints("/foo")
	if len(endpoints) != 1 {
		t.Fatalf("endpoints len = %d, want 1 (replace excludes upstream)", len(endpoints))
	}
	if !strings.HasPrefix(endpoints[0].URL, "https://mirror.corp") {
		t.Errorf("endpoint = %q, want mirror.corp", endpoints[0].URL)
	}
}

// TestMirrorChain_FallbackKeepsUpstream — fallback-mode mirror
// gets tried first, then upstream when the mirror returns 404.
func TestMirrorChain_FallbackKeepsUpstream(t *testing.T) {
	chain := MirrorChain{
		Mirrors: []config.MirrorEntry{
			{URL: "https://mirror.corp", Mode: config.MirrorModeFallback},
		},
		Upstream: "https://upstream.example",
	}
	endpoints := chain.Endpoints("/foo")
	if len(endpoints) != 2 {
		t.Fatalf("endpoints len = %d, want 2 (mirror + upstream)", len(endpoints))
	}
	if !strings.HasPrefix(endpoints[0].URL, "https://mirror.corp") {
		t.Errorf("first endpoint should be the mirror; got %q", endpoints[0].URL)
	}
	if !strings.HasPrefix(endpoints[1].URL, "https://upstream.example") {
		t.Errorf("second endpoint should be upstream; got %q", endpoints[1].URL)
	}
}

// TestMirrorChain_NoMirrorsJustUpstream — empty mirror slate falls
// through directly to the public registry.
func TestMirrorChain_NoMirrorsJustUpstream(t *testing.T) {
	chain := MirrorChain{Upstream: "https://upstream.example"}
	endpoints := chain.Endpoints("/foo")
	if len(endpoints) != 1 || !strings.HasPrefix(endpoints[0].URL, "https://upstream.example") {
		t.Errorf("endpoints = %+v, want one upstream entry", endpoints)
	}
}

// TestMirrorChain_DefaultModeIsReplace — empty Mode is the
// security default (replace, never fall back to upstream).
func TestMirrorChain_DefaultModeIsReplace(t *testing.T) {
	chain := MirrorChain{
		Mirrors:  []config.MirrorEntry{{URL: "https://mirror.corp"}},
		Upstream: "https://upstream.example",
	}
	endpoints := chain.Endpoints("/x")
	if len(endpoints) != 1 {
		t.Fatalf("endpoints len = %d, want 1 (default mode = replace)", len(endpoints))
	}
}

// TestFetchJSON_ReplaceMirrorNeverFallsBackToUpstream — regression
// gate for the corporate-air-gapped invariant: even when the
// replace-mode mirror returns 404, upstream MUST NOT be called.
func TestFetchJSON_ReplaceMirrorNeverFallsBackToUpstream(t *testing.T) {
	var mirrorHits, upstreamHits int32

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&mirrorHits, 1)
		http.NotFound(w, nil)
	}))
	defer mirror.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		_, _ = w.Write([]byte(`{"name":"foo"}`))
	}))
	defer upstream.Close()

	chain := MirrorChain{
		Mirrors:  []config.MirrorEntry{{URL: mirror.URL, Mode: config.MirrorModeReplace}},
		Upstream: upstream.URL,
	}
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/foo", "test",
		func(io.Reader) error { return nil }, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchJSON err = %v, want ErrNotFound (mirror returned 404)", err)
	}
	if atomic.LoadInt32(&mirrorHits) != 1 {
		t.Errorf("mirrorHits = %d, want 1", atomic.LoadInt32(&mirrorHits))
	}
	if atomic.LoadInt32(&upstreamHits) != 0 {
		t.Errorf("upstreamHits = %d, want 0 (replace mode MUST NOT fall back)",
			atomic.LoadInt32(&upstreamHits))
	}
}

// TestFetchJSON_FallbackMirrorReachesUpstream — the fallback mode
// path: mirror returns 404, upstream is then called and returns
// the metadata.
func TestFetchJSON_FallbackMirrorReachesUpstream(t *testing.T) {
	var mirrorHits, upstreamHits int32

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&mirrorHits, 1)
		http.NotFound(w, nil)
	}))
	defer mirror.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		_, _ = w.Write([]byte(`{"name":"foo"}`))
	}))
	defer upstream.Close()

	chain := MirrorChain{
		Mirrors:  []config.MirrorEntry{{URL: mirror.URL, Mode: config.MirrorModeFallback}},
		Upstream: upstream.URL,
	}
	var got struct{ Name string }
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/foo", "test",
		func(r io.Reader) error {
			body, _ := io.ReadAll(r)
			return jsonDecodeAssertOK(body, &got)
		}, nil)
	if err != nil {
		t.Fatalf("FetchJSON: %v", err)
	}
	if got.Name != "foo" {
		t.Errorf("decoded name = %q, want foo", got.Name)
	}
	if atomic.LoadInt32(&mirrorHits) != 1 || atomic.LoadInt32(&upstreamHits) != 1 {
		t.Errorf("mirror=%d upstream=%d, want both 1",
			atomic.LoadInt32(&mirrorHits), atomic.LoadInt32(&upstreamHits))
	}
}

// TestFetchJSON_5xxIsTransient — a 5xx response makes FetchJSON
// surface ErrTransient, even when only 5xx was seen across the
// chain.
func TestFetchJSON_5xxIsTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	chain := MirrorChain{Upstream: server.URL}
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/x", "test",
		func(io.Reader) error { return nil }, nil)
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want ErrTransient on 5xx", err)
	}
}

// TestFetchJSON_429IsTransient — rate-limit responses count as
// transient (Resolver should retry / fall through).
func TestFetchJSON_429IsTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	chain := MirrorChain{Upstream: server.URL}
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/x", "test",
		func(io.Reader) error { return nil }, nil)
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want ErrTransient on 429", err)
	}
}

// TestFetchJSON_AuthAppliedFromMirrorConfig — the bearer token
// from the mirror's auth config lands in the Authorization header.
func TestFetchJSON_AuthAppliedFromMirrorConfig(t *testing.T) {
	t.Setenv("ASTINUS_TEST_AUTH", "secret-bearer")

	var sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"name":"foo"}`))
	}))
	defer server.Close()

	chain := MirrorChain{
		Mirrors: []config.MirrorEntry{{
			URL:  server.URL,
			Mode: config.MirrorModeReplace,
			Auth: &config.MirrorAuthConfig{
				Type: "bearer", TokenEnv: "ASTINUS_TEST_AUTH",
			},
		}},
	}
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/x", "test",
		func(io.Reader) error { return nil }, nil)
	if err != nil {
		t.Fatalf("FetchJSON: %v", err)
	}
	if sawAuth != "Bearer secret-bearer" {
		t.Errorf("server saw Authorization = %q, want bearer header", sawAuth)
	}
}

// TestFetchJSON_CustomHeadersFromMirrorConfig — the per-mirror
// Headers bag (used for the JFrog X-JFrog-Art-Api pattern) reaches
// the server.
func TestFetchJSON_CustomHeadersFromMirrorConfig(t *testing.T) {
	t.Setenv("ASTINUS_TEST_JFROG", "AKCp123")

	var sawHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("X-JFrog-Art-Api")
		_, _ = w.Write([]byte(`{"name":"foo"}`))
	}))
	defer server.Close()

	chain := MirrorChain{
		Mirrors: []config.MirrorEntry{{
			URL:  server.URL,
			Mode: config.MirrorModeReplace,
			Headers: map[string]string{
				"X-JFrog-Art-Api": "${ASTINUS_TEST_JFROG}",
			},
		}},
	}
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/x", "test",
		func(io.Reader) error { return nil }, nil)
	if err != nil {
		t.Fatalf("FetchJSON: %v", err)
	}
	if sawHeader != "AKCp123" {
		t.Errorf("server saw X-JFrog-Art-Api = %q, want AKCp123", sawHeader)
	}
}

// TestJoinURL covers the path-builder helper.
func TestJoinURL(t *testing.T) {
	cases := []struct {
		base, suffix, want string
	}{
		{"https://x.com", "/foo", "https://x.com/foo"},
		{"https://x.com/", "/foo", "https://x.com/foo"},
		{"https://x.com", "foo", "https://x.com/foo"},
		{"https://x.com/api", "", "https://x.com/api"},
	}
	for _, c := range cases {
		if got := joinURL(c.base, c.suffix); got != c.want {
			t.Errorf("joinURL(%q, %q) = %q, want %q", c.base, c.suffix, got, c.want)
		}
	}
}

// jsonDecodeAssertOK is a tiny test helper that decodes JSON and
// returns nil on success. Wrapped so the test reads cleanly.
func jsonDecodeAssertOK(body []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	return dec.Decode(into)
}
