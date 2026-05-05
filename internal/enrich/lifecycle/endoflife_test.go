package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psyf8t/astinus/internal/config"
)

// TestEndOfLifeSource_FetchNodejs — happy path: hit upstream,
// match cycle 20, decode the polymorphic eol/support fields.
func TestEndOfLifeSource_FetchNodejs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodejs.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
			{"cycle": "20", "releaseDate": "2023-04-18", "support": "2024-10-22", "eol": "2026-04-30", "latest": "20.18.0", "lts": true},
			{"cycle": "18", "releaseDate": "2022-04-19", "support": "2023-10-18", "eol": "2025-04-30", "latest": "18.20.4", "lts": true}
		]`))
	}))
	defer server.Close()

	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)
	lc, err := s.Fetch(context.Background(), "nodejs", "20")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if lc == nil || lc.Cycle != "20" {
		t.Fatalf("got %+v", lc)
	}
	if lc.EOL.Format("2006-01-02") != "2026-04-30" {
		t.Errorf("EOL = %v, want 2026-04-30", lc.EOL)
	}
	if !lc.LTS {
		t.Error("expected LTS=true")
	}
}

// TestEndOfLifeSource_PolymorphicEOL — endoflife.date sometimes
// records `eol: true` (EOL but no date) or `eol: false` (not EOL,
// no date scheduled). The decoder MUST handle both without
// panicking.
func TestEndOfLifeSource_PolymorphicEOL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"cycle": "rolling", "releaseDate": "2024-01-01", "eol": false, "lts": false},
			{"cycle": "ancient", "releaseDate": "2010-01-01", "eol": true, "lts": false}
		]`))
	}))
	defer server.Close()
	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)

	rolling, err := s.Fetch(context.Background(), "x", "rolling")
	if err != nil {
		t.Fatalf("rolling: %v", err)
	}
	if rolling.EOLBoolean != "false" {
		t.Errorf("rolling EOLBoolean = %q, want false", rolling.EOLBoolean)
	}
	if !rolling.EOL.IsZero() {
		t.Error("rolling EOL date should be zero")
	}

	ancient, err := s.Fetch(context.Background(), "x", "ancient")
	if err != nil {
		t.Fatalf("ancient: %v", err)
	}
	if ancient.EOLBoolean != "true" {
		t.Errorf("ancient EOLBoolean = %q, want true", ancient.EOLBoolean)
	}
}

// TestEndOfLifeSource_NotFound — a 404 from upstream surfaces as
// ErrNotFound (not a wrapped registry error).
func TestEndOfLifeSource_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)
	_, err := s.Fetch(context.Background(), "nonexistent-product", "1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestEndOfLifeSource_5xxIsTransient — server errors translate
// to ErrTransient so the Resolver can fall back to bundled.
func TestEndOfLifeSource_5xxIsTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)
	_, err := s.Fetch(context.Background(), "x", "1")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want ErrTransient", err)
	}
}

// TestEndOfLifeSource_CycleMismatchReturnsNotFound — upstream
// has product but the requested version doesn't match any cycle.
func TestEndOfLifeSource_CycleMismatchReturnsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"cycle": "20", "releaseDate": "2023-04-18", "lts": true}]`))
	}))
	defer server.Close()
	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)
	_, err := s.Fetch(context.Background(), "nodejs", "12") // 12 not in catalogue
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestEndOfLifeSource_FetchProduct returns every cycle for a
// product (used by `astinus lifecycle update`).
func TestEndOfLifeSource_FetchProduct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"cycle": "22", "lts": true},
			{"cycle": "20", "lts": true},
			{"cycle": "18", "lts": true}
		]`))
	}))
	defer server.Close()
	s := NewEndOfLife(nil, server.Client()).WithUpstream(server.URL)
	cycles, err := s.FetchProduct(context.Background(), "nodejs")
	if err != nil {
		t.Fatalf("FetchProduct: %v", err)
	}
	if len(cycles) != 3 {
		t.Errorf("got %d cycles, want 3", len(cycles))
	}
}

func TestCycleMatches(t *testing.T) {
	cases := map[[2]string]bool{
		{"20", "20"}:     true,
		{"20", "v20"}:    true, // strip leading v
		{"3.11", "3.11"}: true,
		{"20", "18"}:     false,
		{"3.11", "3.12"}: false,
	}
	for k, want := range cases {
		if got := cycleMatches(k[0], k[1]); got != want {
			t.Errorf("cycleMatches(%q, %q) = %v, want %v", k[0], k[1], got, want)
		}
	}
}

func TestSourceMetadata(t *testing.T) {
	s := NewEndOfLife(nil, nil)
	if s.Name() != "endoflife.date" {
		t.Errorf("Name = %q", s.Name())
	}
	if !s.RequiresNetwork() {
		t.Error("EndOfLifeSource must require network")
	}
}

func TestParseDateOrBool(t *testing.T) {
	tm, b := parseDateOrBool([]byte(`"2026-04-30"`))
	if tm.IsZero() || b != "" {
		t.Errorf("date string: got (%v, %q)", tm, b)
	}
	if tm.Format("2006-01-02") != "2026-04-30" {
		t.Errorf("date = %v", tm)
	}
	tm2, b2 := parseDateOrBool([]byte(`true`))
	if !tm2.IsZero() || b2 != "true" {
		t.Errorf("bool true: got (%v, %q)", tm2, b2)
	}
	tm3, b3 := parseDateOrBool([]byte(`false`))
	if !tm3.IsZero() || b3 != "false" {
		t.Errorf("bool false: got (%v, %q)", tm3, b3)
	}
	tm4, b4 := parseDateOrBool(nil)
	if !tm4.IsZero() || b4 != "" {
		t.Errorf("nil: got (%v, %q)", tm4, b4)
	}
}

// TestEndOfLifeSource_MirrorReplace — the corporate-air-gapped
// invariant: a replace-mode mirror NEVER falls back to upstream.
// Reuses the registry package's mirror chain.
func TestEndOfLifeSource_MirrorReplace(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		_, _ = w.Write([]byte(`[{"cycle":"20","releaseDate":"2023-04-18","lts":true}]`))
	}))
	defer upstream.Close()

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer mirror.Close()

	// We cannot import config here without a circular dep risk —
	// we use the source's WithUpstream + a synthesised mirror via
	// the package-level registry.MirrorChain (already imported).
	// Easier path: route via NewEndOfLife with a mirror entry
	// constructed from the test server.
	src := newEndOfLifeWithMirror(t, mirror.URL, true /* replace */)
	src.WithUpstream(upstream.URL)
	_, err := src.Fetch(context.Background(), "nodejs", "20")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound (mirror returned 404, replace mode = no fallback)", err)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream called %d times under replace mode (must be 0)", upstreamHits)
	}
}

// TestEndOfLifeSource_MirrorFallback — fallback mode: mirror
// returns 404, upstream is then called and serves the data.
func TestEndOfLifeSource_MirrorFallback(t *testing.T) {
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer mirror.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"cycle":"20","releaseDate":"2023-04-18","lts":true}]`))
	}))
	defer upstream.Close()

	src := newEndOfLifeWithMirror(t, mirror.URL, false /* fallback */)
	src.WithUpstream(upstream.URL)
	lc, err := src.Fetch(context.Background(), "nodejs", "20")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if lc == nil || lc.Cycle != "20" {
		t.Errorf("got %+v", lc)
	}
}

// newEndOfLifeWithMirror constructs an EndOfLifeSource with a
// single MirrorEntry pointing at mirrorURL. replace=true uses
// MirrorModeReplace, false uses MirrorModeFallback.
func newEndOfLifeWithMirror(_ *testing.T, mirrorURL string, replace bool) *EndOfLifeSource {
	mode := config.MirrorModeFallback
	if replace {
		mode = config.MirrorModeReplace
	}
	mirrors := []config.MirrorEntry{{
		Ecosystem: "lifecycle",
		URL:       mirrorURL,
		Mode:      mode,
	}}
	return NewEndOfLife(mirrors, http.DefaultClient)
}
