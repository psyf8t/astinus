package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// hangServer accepts the request, sends partial-or-no headers, then
// blocks until the request context fires. Mirrors the run-#4
// reproducer: established TCP connection idle indefinitely.
func hangServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(s.Close)
	return s
}

// TestMultiSourceResolver_AutoModeHonoursPerCallTimeout drives a
// real NVDAPISource at a hung-server backend and asserts that
// ResolveCtx respects the per-call deadline and that the source is
// marked unavailable for subsequent calls. Auto mode never returns
// an error to the enricher. S6 Task 0 / ADR-0057.
func TestMultiSourceResolver_AutoModeHonoursPerCallTimeout(t *testing.T) {
	srv := hangServer(t)
	nvd := NewNVDAPI("", &http.Client{}).WithBaseURL(srv.URL)

	resolver := NewMultiSource(Options{
		Mode:             ModeAuto,
		Sources:          []Source{nvd},
		PerSourceTimeout: 5 * time.Second,
		PerCallTimeout:   200 * time.Millisecond,
	})

	start := time.Now()
	cands, err := resolver.ResolveCtx(context.Background(), cpe.PURL{
		Type: "npm", Name: "express", Version: "4.18.2",
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("auto mode returned err %v, want nil (graceful skip)", err)
	}
	if len(cands) != 0 {
		t.Errorf("got %d candidates, expected 0 (hung server)", len(cands))
	}
	if elapsed > time.Second {
		t.Errorf("ResolveCtx took %v, expected ≤ 1s — per-call deadline did not fire", elapsed)
	}
	statuses := resolver.SourceStatuses()
	if got := statuses["nvd-api"]; got != "timeout" {
		t.Errorf("source-status[nvd-api] = %q, want timeout", got)
	}

	// Second call: source should be skipped — budget marked exhausted.
	start2 := time.Now()
	_, err2 := resolver.ResolveCtx(context.Background(), cpe.PURL{
		Type: "npm", Name: "lodash", Version: "4.17.21",
	})
	if err2 != nil {
		t.Errorf("second call err = %v, want nil", err2)
	}
	if elapsed2 := time.Since(start2); elapsed2 > 100*time.Millisecond {
		t.Errorf("second call took %v — exhausted budget did not short-circuit", elapsed2)
	}
}

// TestMultiSourceResolver_HybridModeReturnsErrSourceUnavailable drives
// the same fixture in --cpe-mode hybrid and asserts that the first
// per-call timeout surfaces ErrSourceUnavailable so the CLI can
// exit 60. ADR-0051 / ADR-0057.
func TestMultiSourceResolver_HybridModeReturnsErrSourceUnavailable(t *testing.T) {
	srv := hangServer(t)
	nvd := NewNVDAPI("", &http.Client{}).WithBaseURL(srv.URL)

	resolver := NewMultiSource(Options{
		Mode:             ModeHybrid,
		Sources:          []Source{nvd},
		PerSourceTimeout: 5 * time.Second,
		PerCallTimeout:   200 * time.Millisecond,
	})

	_, err := resolver.ResolveCtx(context.Background(), cpe.PURL{
		Type: "npm", Name: "express", Version: "4.18.2",
	})
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Errorf("hybrid mode err = %v, want ErrSourceUnavailable", err)
	}
}
