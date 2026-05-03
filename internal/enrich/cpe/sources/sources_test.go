package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// ─── PatternMatcher / Heuristic ────────────────────────────────────

func TestPatternMatcherWrapsBundled(t *testing.T) {
	pm := NewPatternMatcher()
	if pm.Name() != "pattern-matcher" {
		t.Errorf("Name = %q", pm.Name())
	}
	if pm.RequiresNetwork() {
		t.Error("PatternMatcher must not require network")
	}
	if pm.Priority() != 100 {
		t.Errorf("Priority = %d, want 100", pm.Priority())
	}
	// Use a known bundled entry: pkg:npm/express → expressjs/express
	out, err := pm.Match(context.Background(), cpe.PURL{Type: "npm", Name: "express", Version: "4.18.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected a bundled match for express")
	}
	if !strings.Contains(out[0].CPE, "expressjs:express") {
		t.Errorf("CPE = %q, want to contain expressjs:express", out[0].CPE)
	}
	if out[0].Source != cpe.SourceBundled {
		t.Errorf("Source = %q", out[0].Source)
	}
}

func TestHeuristicAlwaysFires(t *testing.T) {
	h := NewHeuristic()
	if h.Priority() != 50 {
		t.Errorf("Priority = %d, want 50", h.Priority())
	}
	out, err := h.Match(context.Background(), cpe.PURL{Type: "npm", Name: "totally-unknown-pkg", Version: "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("heuristic should always emit at least one match")
	}
	if out[0].Confidence != cpe.ConfidenceLow {
		t.Errorf("Confidence = %q, want low", out[0].Confidence)
	}
}

// ─── LocalDict ────────────────────────────────────────────────────

func TestLocalDictNilWrapping(t *testing.T) {
	if NewLocalDict(nil) != nil {
		t.Error("NewLocalDict(nil) must return nil so the orchestrator drops it")
	}
}

func TestLocalDictBasics(t *testing.T) {
	r := cpe.NewLocalDictionaryResolver()
	src := NewLocalDict(r)
	if src == nil {
		t.Fatal("NewLocalDict returned nil for non-nil resolver")
	}
	if src.Name() != "local-dictionary" {
		t.Errorf("Name = %q", src.Name())
	}
	if src.RequiresNetwork() {
		t.Error("LocalDict must not require network")
	}
	if src.Priority() != 90 {
		t.Errorf("Priority = %d, want 90", src.Priority())
	}
	out, err := src.Match(context.Background(), cpe.PURL{Type: "npm", Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("empty resolver should return no matches, got %+v", out)
	}
}

// ─── ClearlyDefined ────────────────────────────────────────────────

func TestClearlyDefinedHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/definitions/") {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"described": map[string]any{
				"identifiers": map[string]any{
					"cpe": []string{"cpe:2.3:a:expressjs:express:4.18.0:*:*:*:*:*:*:*"},
				},
			},
		})
	}))
	defer srv.Close()

	src := NewClearlyDefined(nil).WithBaseURL(srv.URL)
	out, err := src.Match(context.Background(), cpe.PURL{Type: "npm", Name: "express", Version: "4.18.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("matches = %d, want 1", len(out))
	}
	if !strings.Contains(out[0].CPE, "expressjs:express") {
		t.Errorf("CPE = %q", out[0].CPE)
	}
	if out[0].Source != cpe.Source("clearly-defined") {
		t.Errorf("Source = %q", out[0].Source)
	}
}

func TestClearlyDefined404IsNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	src := NewClearlyDefined(nil).WithBaseURL(srv.URL)
	out, err := src.Match(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if err != nil {
		t.Errorf("404 should not be an error, got %v", err)
	}
	if out != nil {
		t.Errorf("matches = %+v, want nil", out)
	}
}

func TestClearlyDefined5xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	src := NewClearlyDefined(nil).WithBaseURL(srv.URL)
	if _, err := src.Match(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"}); err == nil {
		t.Fatal("expected error on 5xx")
	}
}

func TestClearlyDefinedSkipsUntranslatablePURLs(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()
	src := NewClearlyDefined(nil).WithBaseURL(srv.URL)
	// PURL with no version → no coordinate possible.
	if _, err := src.Match(context.Background(), cpe.PURL{Type: "npm", Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("clearly-defined should not be queried for unmappable PURLs")
	}
}

func TestPurlToCDCoordinatesTable(t *testing.T) {
	cases := []struct {
		purl cpe.PURL
		want string
	}{
		{cpe.PURL{Type: "npm", Name: "express", Version: "4.18.0"}, "npm/npmjs/-/express/4.18.0"},
		{cpe.PURL{Type: "npm", Namespace: "@types", Name: "node", Version: "20"}, "npm/npmjs/@types/node/20"},
		{cpe.PURL{Type: "pypi", Name: "django", Version: "5.0"}, "pypi/pypi/-/django/5.0"},
		{cpe.PURL{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.14.0"},
			"maven/mavencentral/org.apache.commons/commons-lang3/3.14.0"},
		{cpe.PURL{Type: "gem", Name: "rake", Version: "13.1.0"}, "gem/rubygems/-/rake/13.1.0"},
		{cpe.PURL{Type: "cargo", Name: "rocket", Version: "0.5.0"}, "crate/cratesio/-/rocket/0.5.0"},
		{cpe.PURL{Type: "nuget", Name: "Newtonsoft.Json", Version: "13.0"}, "nuget/nuget/-/Newtonsoft.Json/13.0"},
	}
	for _, tc := range cases {
		got, ok := purlToCDCoordinates(tc.purl)
		if !ok || got != tc.want {
			t.Errorf("purl %+v → (%q, %v), want (%q, true)", tc.purl, got, ok, tc.want)
		}
	}

	// Unmappable cases.
	for _, p := range []cpe.PURL{
		{Type: "deb", Name: "x", Version: "1"},
		{Type: "npm", Name: "x"},                 // no version
		{Type: "maven", Name: "x", Version: "1"}, // no namespace
	} {
		if _, ok := purlToCDCoordinates(p); ok {
			t.Errorf("purl %+v should be unmappable", p)
		}
	}
}

// ─── NVD API ───────────────────────────────────────────────────────

func TestNVDAPIHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"products": []map[string]any{
				{"cpe": map[string]string{"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}},
				{"cpe": map[string]string{"cpeName": "cpe:2.3:a:apache:log4j:2.13.0:*:*:*:*:*:*:*"}},
			},
		})
	}))
	defer srv.Close()
	src := NewNVDAPI("", nil).WithBaseURL(srv.URL)
	out, err := src.Match(context.Background(), cpe.PURL{Type: "maven", Name: "log4j", Version: "2.14.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("matches = %d, want 1 (version filter must drop 2.13.0)", len(out))
	}
	if !strings.Contains(out[0].CPE, "log4j:2.14.1") {
		t.Errorf("CPE = %q", out[0].CPE)
	}
}

func TestNVDAPIRateLimit429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	src := NewNVDAPI("", nil).WithBaseURL(srv.URL)
	_, err := src.Match(context.Background(), cpe.PURL{Type: "maven", Name: "x", Version: "1"})
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("error = %v, want to mention rate-limit", err)
	}
}

func TestNVDAPIEmptyName(t *testing.T) {
	src := NewNVDAPI("", nil)
	out, err := src.Match(context.Background(), cpe.PURL{Type: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("empty PURL.Name should return nil, got %+v", out)
	}
}

func TestNVDAPIPriority(t *testing.T) {
	if (&NVDAPISource{}).Priority() != 80 {
		t.Errorf("NVD priority should be 80")
	}
	if !(&NVDAPISource{}).RequiresNetwork() {
		t.Errorf("NVD must require network")
	}
}

// ─── tokenBucket ──────────────────────────────────────────────────

func TestTokenBucketRespectsContextCancel(t *testing.T) {
	b := newTokenBucket(0.001, 1) // 1000 s per token
	// First Wait succeeds (initial token).
	ctx := context.Background()
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	// Second Wait would block ~1000 s; cancel early.
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	err := b.Wait(ctx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestTokenBucketAllowsBurstThenSerialises(t *testing.T) {
	b := newTokenBucket(1000, 3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := b.Wait(ctx); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	// 4th token would refill quickly at 1000 rps, so this should
	// also succeed without blocking the test for long.
	if err := b.Wait(ctx); err != nil {
		t.Fatalf("post-burst: %v", err)
	}
}
