package cpe

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// slowResolver is a ContextResolver that sleeps `delay` per call and
// optionally returns errFromResolve once `failAfter` calls have
// elapsed. Used to drive the wall-time-bound tests without spinning
// up an httptest.Server in this package (sources/ has those tests).
type slowResolver struct {
	delay     time.Duration
	failAfter int
	calls     int
	errFromR  error
	// statuses is the per-source completion map this resolver
	// pretends to expose; mirrors MultiSourceResolver's surface so
	// the enricher's resolverStatuses() type-asserts and reads it.
	statuses map[string]string
}

func (s *slowResolver) Resolve(p PURL) []Candidate {
	cands, _ := s.ResolveCtx(context.Background(), p)
	return cands
}

func (s *slowResolver) ResolveCtx(ctx context.Context, p PURL) ([]Candidate, error) {
	s.calls++
	if s.failAfter > 0 && s.calls > s.failAfter {
		return nil, s.errFromR
	}
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

func (s *slowResolver) SourceStatuses() map[string]string {
	if s.statuses == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(s.statuses))
	for k, v := range s.statuses {
		out[k] = v
	}
	return out
}

func makeSBOM(n int) *model.SBOM {
	comps := make([]model.Component, n)
	for i := 0; i < n; i++ {
		comps[i] = model.Component{
			Name:    "pkg",
			Version: "1.0.0",
			PURL:    "pkg:npm/pkg-x@1.0.0",
		}
	}
	return &model.SBOM{Components: comps}
}

// TestEnricher_TotalCapBoundsWallTime asserts that Enrich respects
// the total wall-time cap when the resolver would otherwise wedge
// for far longer than the budget. S6 Task 0.
func TestEnricher_TotalCapBoundsWallTime(t *testing.T) {
	sbom := makeSBOM(50)
	res := &slowResolver{
		delay: 200 * time.Millisecond,
		statuses: map[string]string{
			"online-nvd": "complete",
		},
	}
	e := NewWithResolver(res).WithTotalCap(300 * time.Millisecond)

	start := time.Now()
	err := e.Enrich(context.Background(), sbom, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("auto mode Enrich err = %v, want nil (partial emit)", err)
	}
	if elapsed > 800*time.Millisecond {
		t.Errorf("Enrich took %v, expected ≤ 800ms — total cap did not fire", elapsed)
	}
	if got := sbom.Metadata.Properties[model.PropertyCPETotalCapHit]; got != "true" {
		t.Errorf("total-cap-hit = %q, want true", got)
	}
	if got := sbom.Metadata.Properties[model.PropertyCPEElapsedSeconds]; got == "" {
		t.Error("elapsed-seconds missing on metadata")
	}
	if got := sbom.Metadata.Properties[model.PropertyCPEComponentsProcessed]; got == "" {
		t.Error("components-processed missing on metadata")
	}
	if got := sbom.Metadata.Properties[model.PropertyCPESourceStatusPrefix+"online-nvd"]; got != "complete" {
		t.Errorf("source-status[online-nvd] = %q, want complete", got)
	}
}

// TestEnricher_StrictModeReturnsErrSourceUnavailable asserts that
// strict-mode (--cpe-mode hybrid) surfaces a ResolveCtx error as
// cpe.ErrSourceUnavailable, which the CLI maps to exit 60.
// S6 Task 0 / ADR-0057.
func TestEnricher_StrictModeReturnsErrSourceUnavailable(t *testing.T) {
	sbom := makeSBOM(5)
	res := &slowResolver{
		delay:     1 * time.Millisecond,
		failAfter: 1,
		// emulate the orchestrator's ErrSourceUnavailable bubbling up
		errFromR: ErrSourceUnavailable,
	}
	e := NewWithResolver(res).WithStrictMode(true).WithTotalCap(time.Minute)

	err := e.Enrich(context.Background(), sbom, nil)
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Errorf("strict-mode err = %v, want ErrSourceUnavailable", err)
	}
}

// TestEnricher_DefaultOptions pins the default wall-time bounds the
// CLI advertises in `--help`. ADR-0057 calibrated 3m/60s/10s on
// airflow-class images.
func TestEnricher_DefaultOptions(t *testing.T) {
	e := New()
	if e.totalCap != DefaultTotalCap {
		t.Errorf("default totalCap = %v, want %v", e.totalCap, DefaultTotalCap)
	}
	if DefaultTotalCap != 3*time.Minute {
		t.Errorf("DefaultTotalCap = %v, want 3m", DefaultTotalCap)
	}
	if DefaultSourceTimeout != 60*time.Second {
		t.Errorf("DefaultSourceTimeout = %v, want 60s", DefaultSourceTimeout)
	}
	if DefaultCallTimeout != 10*time.Second {
		t.Errorf("DefaultCallTimeout = %v, want 10s", DefaultCallTimeout)
	}
}

// TestEnricher_ProgressLogsByCount asserts that the enricher emits a
// `cpe.enricher.progress` log every N components. Drives a small
// fixture with cadence override so the test runs quickly.
func TestEnricher_ProgressLogsByCount(t *testing.T) {
	sbom := makeSBOM(50)
	res := &slowResolver{delay: 0}
	e := NewWithResolver(res).
		WithTotalCap(time.Minute).
		WithProgressTuning(10, time.Hour) // count-only cadence

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich err = %v", err)
	}
	count := strings.Count(buf.String(), "cpe.enricher.progress")
	// 50 components / 10 every-N = 5 progress log entries (firing at
	// 10, 20, 30, 40, 50). Tolerate ±1 for boundary semantics.
	if count < 4 || count > 6 {
		t.Errorf("got %d progress log entries, want ~5\nlogs:\n%s", count, buf.String())
	}
}

// TestEnricher_TotalCapDisabled covers the legacy / test path where
// WithTotalCap(0) skips the outer context deadline. The Enrich call
// completes irrespective of wall-time. S6 Task 0.
func TestEnricher_TotalCapDisabled(t *testing.T) {
	sbom := makeSBOM(3)
	res := &slowResolver{delay: 10 * time.Millisecond}
	e := NewWithResolver(res).WithTotalCap(0)

	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Errorf("Enrich err = %v, want nil", err)
	}
	if got := sbom.Metadata.Properties[model.PropertyCPETotalCapHit]; got != "false" {
		t.Errorf("total-cap-hit = %q, want false", got)
	}
}
