package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// fakeSource is a configurable Source for testing the orchestrator's
// dispatch / mode / cache behaviour without involving real HTTP.
type fakeSource struct {
	name      string
	priority  int
	online    bool
	matches   []cpe.Match
	err       error
	callCount int
}

func (f *fakeSource) Name() string          { return f.name }
func (f *fakeSource) Priority() int         { return f.priority }
func (f *fakeSource) RequiresNetwork() bool { return f.online }
func (f *fakeSource) Match(_ context.Context, _ cpe.PURL) ([]cpe.Match, error) {
	f.callCount++
	return f.matches, f.err
}

// ─── Mode filter ──────────────────────────────────────────────────────

func TestModeOfflineDropsOnlineSources(t *testing.T) {
	online := &fakeSource{name: "nvd", priority: 80, online: true,
		matches: []cpe.Match{{CPE: "cpe:online", Confidence: cpe.ConfidenceHigh}}}
	offline := &fakeSource{name: "bundled", priority: 100, online: false,
		matches: []cpe.Match{{CPE: "cpe:offline", Confidence: cpe.ConfidenceHigh}}}

	r := NewMultiSource(Options{
		Mode:    ModeOffline,
		Sources: []Source{online, offline},
	})
	if got := len(r.Sources()); got != 1 {
		t.Fatalf("Sources() len = %d, want 1 (online dropped)", got)
	}

	r.Resolve(cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if online.callCount != 0 {
		t.Errorf("online source was called %d times in offline mode (want 0)", online.callCount)
	}
	if offline.callCount != 1 {
		t.Errorf("offline source called %d times (want 1)", offline.callCount)
	}
}

func TestModeOnlineKeepsAllSources(t *testing.T) {
	online := &fakeSource{name: "nvd", priority: 80, online: true}
	offline := &fakeSource{name: "bundled", priority: 100, online: false}
	r := NewMultiSource(Options{
		Mode:    ModeOnline,
		Sources: []Source{online, offline},
	})
	if got := len(r.Sources()); got != 2 {
		t.Errorf("Sources len = %d, want 2", got)
	}
}

func TestModeUnknownDefaultsToHybrid(t *testing.T) {
	r := NewMultiSource(Options{Mode: "garbage"})
	if r.Mode() != ModeHybrid {
		t.Errorf("Mode = %q, want hybrid (unknown should default)", r.Mode())
	}
}

// ─── Priority sort ────────────────────────────────────────────────────

func TestSourcesSortedByPriorityDesc(t *testing.T) {
	a := &fakeSource{name: "low", priority: 50}
	b := &fakeSource{name: "high", priority: 100}
	c := &fakeSource{name: "mid", priority: 80}
	r := NewMultiSource(Options{Sources: []Source{a, b, c}})
	got := r.Sources()
	if got[0].Name() != "high" || got[1].Name() != "mid" || got[2].Name() != "low" {
		t.Errorf("order = [%s, %s, %s], want [high, mid, low]",
			got[0].Name(), got[1].Name(), got[2].Name())
	}
}

func TestNilSourcesDropped(t *testing.T) {
	r := NewMultiSource(Options{
		Sources: []Source{nil, &fakeSource{name: "real"}, nil},
	})
	if got := len(r.Sources()); got != 1 {
		t.Errorf("len = %d, want 1 (nil dropped)", got)
	}
}

// ─── Hybrid early-exit ────────────────────────────────────────────────

func TestHybridSkipsOnlineWhenOfflineHighConfidence(t *testing.T) {
	offlineHigh := &fakeSource{name: "bundled", priority: 100, online: false,
		matches: []cpe.Match{{CPE: "cpe:bundled", Confidence: cpe.ConfidenceHigh}}}
	online := &fakeSource{name: "nvd", priority: 80, online: true,
		matches: []cpe.Match{{CPE: "cpe:nvd", Confidence: cpe.ConfidenceHigh}}}

	r := NewMultiSource(Options{
		Mode:    ModeHybrid,
		Sources: []Source{offlineHigh, online},
	})
	out := r.Resolve(cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if len(out) != 1 || out[0].CPE != "cpe:bundled" {
		t.Errorf("matches = %+v, want one bundled hit", out)
	}
	if online.callCount != 0 {
		t.Errorf("online source was called in hybrid + offline-high (calls = %d)", online.callCount)
	}
}

func TestHybridQueriesOnlineWhenOfflineLowConfidence(t *testing.T) {
	offlineLow := &fakeSource{name: "heuristic", priority: 50, online: false,
		matches: []cpe.Match{{CPE: "cpe:heuristic", Confidence: cpe.ConfidenceLow}}}
	online := &fakeSource{name: "nvd", priority: 80, online: true,
		matches: []cpe.Match{{CPE: "cpe:nvd", Confidence: cpe.ConfidenceHigh}}}

	r := NewMultiSource(Options{
		Mode:    ModeHybrid,
		Sources: []Source{offlineLow, online},
	})
	out := r.Resolve(cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if online.callCount == 0 {
		t.Errorf("online source must be called when offline confidence is low")
	}
	if len(out) < 2 {
		t.Errorf("matches = %+v, want both offline + online entries", out)
	}
}

// ─── Cache ────────────────────────────────────────────────────────────

func TestCacheAvoidsRepeatedSourceCalls(t *testing.T) {
	s := &fakeSource{name: "x", priority: 100,
		matches: []cpe.Match{{CPE: "cpe:test", Confidence: cpe.ConfidenceHigh}}}
	r := NewMultiSource(Options{Sources: []Source{s}})
	purl := cpe.PURL{Type: "npm", Name: "lodash", Version: "1"}
	for i := 0; i < 5; i++ {
		r.Resolve(purl)
	}
	if s.callCount != 1 {
		t.Errorf("source called %d times, want 1 (cache should suppress repeats)", s.callCount)
	}
}

func TestCacheRecordsEmptyResults(t *testing.T) {
	s := &fakeSource{name: "x", priority: 100, matches: nil}
	r := NewMultiSource(Options{Sources: []Source{s}})
	purl := cpe.PURL{Type: "npm", Name: "lodash"}
	for i := 0; i < 3; i++ {
		out := r.Resolve(purl)
		if len(out) != 0 {
			t.Errorf("expected empty result, got %v", out)
		}
	}
	if s.callCount != 1 {
		t.Errorf("source called %d times for empty result, want 1", s.callCount)
	}
}

// ─── Errors ──────────────────────────────────────────────────────────

func TestErrorDoesNotAbortChain(t *testing.T) {
	broken := &fakeSource{name: "broken", priority: 100, err: errors.New("boom")}
	working := &fakeSource{name: "working", priority: 80,
		matches: []cpe.Match{{CPE: "cpe:test", Confidence: cpe.ConfidenceHigh}}}
	r := NewMultiSource(Options{Sources: []Source{broken, working}})
	out := r.Resolve(cpe.PURL{Type: "npm", Name: "x"})
	if len(out) == 0 {
		t.Errorf("broken source aborted chain; expected working source's result")
	}
}

// ─── Offline-mode-no-network gate ────────────────────────────────────

// TestOfflineModeMakesZeroHTTPCalls — Definition-of-Done gate from
// the task spec: offline mode MUST make zero outbound HTTP calls.
// Wires real ClearlyDefined + NVDAPI sources behind an httptest
// server that increments a counter on every request, then runs the
// orchestrator over a batch of representative PURLs and asserts
// the counter stays at 0.
func TestOfflineModeMakesZeroHTTPCalls(t *testing.T) {
	calls := 0
	srv := newRecordingServer(t, &calls)
	defer srv.Close()

	httpClient := srv.Client()
	cd := NewClearlyDefined(httpClient)
	cd.WithBaseURL(srv.URL)
	nvd := NewNVDAPI("", httpClient)
	nvd.WithBaseURL(srv.URL)

	r := NewMultiSource(Options{
		Mode: ModeOffline,
		Sources: []Source{
			NewPatternMatcher(),
			cd,
			nvd,
			NewHeuristic(),
		},
	})

	purls := []cpe.PURL{
		{Type: "npm", Name: "express", Version: "4.18.0"},
		{Type: "pypi", Name: "django", Version: "5.0"},
		{Type: "maven", Namespace: "org.apache.logging.log4j", Name: "log4j-core", Version: "2.14.1"},
		{Type: "cargo", Name: "rocket", Version: "0.5.0"},
	}
	for _, p := range purls {
		_ = r.Resolve(p)
	}

	if calls != 0 {
		t.Errorf("offline mode made %d HTTP calls, want 0", calls)
	}
}

// newRecordingServer returns an httptest server whose handler
// increments the supplied counter on every request. Used by the
// offline-mode-no-network gate.
func newRecordingServer(t *testing.T, counter *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		*counter++
	}))
}

// ─── Cache helper ─────────────────────────────────────────────────────

func TestCacheNilSafe(t *testing.T) {
	var c *Cache
	if _, ok := c.Get("anything"); ok {
		t.Error("nil cache Get should miss")
	}
	c.Set("x", nil) // must not panic
	if c.Size() != 0 {
		t.Errorf("Size = %d", c.Size())
	}
}

func TestCacheGetSet(t *testing.T) {
	c := NewCache()
	if _, ok := c.Get("k"); ok {
		t.Error("empty cache should miss")
	}
	c.Set("k", []cpe.Match{{CPE: "cpe:x"}})
	got, ok := c.Get("k")
	if !ok || len(got) != 1 || got[0].CPE != "cpe:x" {
		t.Errorf("Get = (%+v, %v)", got, ok)
	}
	if c.Size() != 1 {
		t.Errorf("Size = %d", c.Size())
	}
}
