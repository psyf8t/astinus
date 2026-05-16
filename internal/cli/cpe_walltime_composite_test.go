package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestCPEEnricher_CompositeReproducer_HangServerBoundedByTotalCap is
// the Sprint 9 Task 0 "real-image proxy" pin. Wires the full
// CLI-built CPE stack against a hung httptest server in one call:
//
//	buildCPESourceHTTPClient  →  cpesources.NewNVDAPI
//	  →  cpesources.NewMultiSource  →  cpe.NewWithResolver  →  Enrich
//
// The hung handler mirrors the production Cloudflare-fronted
// failure shape (TCP connection established, no response headers,
// no close — handler blocks on r.Context().Done()). The four S6/S7/
// S8 defense layers are individually pinned by sources/hang_test.go,
// walltime_test.go, and cpe_http_client_test.go; this composite
// test asserts they compose correctly through the same data path
// the CLI runs in production.
//
// Timing budget scaled to be CI-friendly: 2 s total cap / 500 ms
// per-source / 200 ms per-call. Production defaults are 3 m / 60 s
// / 10 s (calibrated for Airflow-class images, see ADR-0057). The
// ratio is preserved, so a regression that bypasses any of the four
// layers fails identically at unit and production scale.
//
// S9 Task 0 / ADR-0057 amendment.
func TestCPEEnricher_CompositeReproducer_HangServerBoundedByTotalCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	const (
		totalCap         = 2 * time.Second
		perSourceTimeout = 500 * time.Millisecond
		perCallTimeout   = 200 * time.Millisecond
		componentCount   = 50
	)

	client := buildCPESourceHTTPClient(&http.Transport{}, perCallTimeout)
	nvd := cpesources.NewNVDAPI("", client).WithBaseURL(srv.URL)

	resolver := cpesources.NewMultiSource(cpesources.Options{
		Mode:             cpesources.ModeAuto,
		Sources:          []cpesources.Source{nvd},
		PerSourceTimeout: perSourceTimeout,
		PerCallTimeout:   perCallTimeout,
	})
	enricher := cpe.NewWithResolver(resolver).WithTotalCap(totalCap)

	comps := make([]model.Component, componentCount)
	for i := 0; i < componentCount; i++ {
		comps[i] = model.Component{
			Name:    "express",
			Version: "4.18.2",
			PURL:    "pkg:npm/express@4.18.2",
		}
	}
	sbom := &model.SBOM{Components: comps}

	start := time.Now()
	if err := enricher.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("auto-mode Enrich returned err = %v, want nil (partial emit)", err)
	}
	elapsed := time.Since(start)

	// The four layers compose: the first component trips the per-call
	// deadline (200ms), the SourceBudget marks `nvd-api` exhausted,
	// every subsequent component short-circuits at the budget check
	// without dialing the hung server again. A regression that
	// bypasses any layer (e.g. a transport that swallows ctx.Done,
	// or a budget that fails to mark exhausted) elapses at least
	// componentCount·perCallTimeout = 50·200ms = 10s on this
	// fixture, far above the soft ceiling below.
	softCeiling := perCallTimeout + perSourceTimeout + 1*time.Second
	if elapsed > softCeiling {
		t.Errorf("composite Enrich elapsed %v, want ≤ %v — four-layer defense did not bound the run",
			elapsed, softCeiling)
	}
	if elapsed >= totalCap {
		t.Errorf("composite Enrich elapsed %v reached total cap %v — per-source budget did not short-circuit",
			elapsed, totalCap)
	}

	// Stage A reproducer fingerprint — the S6-T0 stamps must
	// be present on every completed Enrich run.
	if got := sbom.Metadata.Properties[model.PropertyCPEElapsedSeconds]; got == "" {
		t.Errorf("%s missing, want non-empty (S6-T0 stamp)",
			model.PropertyCPEElapsedSeconds)
	}
	if got := sbom.Metadata.Properties[model.PropertyCPEComponentsProcessed]; got == "" {
		t.Errorf("%s missing, want non-empty (S6-T0 stamp)",
			model.PropertyCPEComponentsProcessed)
	}
	// S8-T0 configured stamps surface the operator-supplied
	// bounds through the MultiSourceResolver.Timeouts() accessor.
	if got := sbom.Metadata.Properties[model.PropertyCPETotalCapConfigured]; got != totalCap.String() {
		t.Errorf("%s = %q, want %q (S8-T0 stamp)",
			model.PropertyCPETotalCapConfigured, got, totalCap.String())
	}
	if got := sbom.Metadata.Properties[model.PropertyCPESourceTimeoutConfigured]; got != perSourceTimeout.String() {
		t.Errorf("%s = %q, want %q (S8-T0 stamp)",
			model.PropertyCPESourceTimeoutConfigured, got, perSourceTimeout.String())
	}
	if got := sbom.Metadata.Properties[model.PropertyCPECallTimeoutConfigured]; got != perCallTimeout.String() {
		t.Errorf("%s = %q, want %q (S8-T0 stamp)",
			model.PropertyCPECallTimeoutConfigured, got, perCallTimeout.String())
	}

	// Per-source status confirms the per-call deadline tripped
	// `nvd-api` and the budget marked it unavailable for subsequent
	// calls — the second defense layer firing in sequence after the
	// first.
	statusKey := model.PropertyCPESourceStatusPrefix + "nvd-api"
	got := sbom.Metadata.Properties[statusKey]
	if got == "" {
		t.Errorf("%s missing, want non-empty (S6-T0 per-source stamp)", statusKey)
	}
	// nvd-api should be flagged as timeout / budget-exhausted /
	// errored — anything except `complete` (which would mean the
	// hung server somehow responded).
	if got == "complete" {
		t.Errorf("%s = %q, want non-complete — hung server should not look complete",
			statusKey, got)
	}
}

// TestCPEEnricher_CompositeReproducer_TotalCapFiresOnSlowSource is the
// companion S9-T0 pin that exercises the third defense layer (total
// enricher cap) in isolation. Uses a registered Source stub that
// delays each call long enough to evade the per-source budget but
// short enough to hit the total cap. The point: prove the
// `context.WithTimeout(ctx, e.totalCap)` outer bound fires even
// when per-source defenses don't.
//
// S9 Task 0 / ADR-0057 amendment.
func TestCPEEnricher_CompositeReproducer_TotalCapFiresOnSlowSource(t *testing.T) {
	const (
		totalCap       = 500 * time.Millisecond
		perCallTimeout = 5 * time.Second // intentionally far above totalCap
	)

	src := &slowCPESource{delay: 200 * time.Millisecond}
	resolver := cpesources.NewMultiSource(cpesources.Options{
		Mode:             cpesources.ModeAuto,
		Sources:          []cpesources.Source{src},
		PerSourceTimeout: 10 * time.Second, // intentionally far above totalCap
		PerCallTimeout:   perCallTimeout,
	})
	enricher := cpe.NewWithResolver(resolver).WithTotalCap(totalCap)

	// Unique PURLs per component so the resolver's per-PURL cache
	// doesn't short-circuit the 49 subsequent calls. Each Match
	// call takes ~200 ms; the second component's call would push
	// elapsed past the 500 ms total cap.
	comps := make([]model.Component, 50)
	for i := 0; i < 50; i++ {
		comps[i] = model.Component{
			Name:    "pkg-" + string(rune('A'+i%26)) + string(rune('a'+i/26)),
			Version: "1.0.0",
			PURL:    "pkg:npm/pkg-" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + "@1.0.0",
		}
	}
	sbom := &model.SBOM{Components: comps}

	start := time.Now()
	if err := enricher.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("auto-mode Enrich returned err = %v, want nil (partial emit)", err)
	}
	elapsed := time.Since(start)

	if elapsed > totalCap+1*time.Second {
		t.Errorf("Enrich elapsed %v, want ≤ %v — total cap (third layer) did not fire",
			elapsed, totalCap+1*time.Second)
	}
	if got := sbom.Metadata.Properties[model.PropertyCPETotalCapHit]; got != "true" {
		t.Errorf("%s = %q, want true — total cap fingerprint missing",
			model.PropertyCPETotalCapHit, got)
	}
}

// slowCPESource is a test-only Source that sleeps `delay` per
// Match call. Used to drive the total-cap defense layer in
// isolation; per-call deadlines are configured wide enough that
// the per-call defense doesn't fire first.
type slowCPESource struct {
	delay time.Duration
}

func (s *slowCPESource) Name() string { return "slow-stub" }

func (s *slowCPESource) Match(ctx context.Context, _ cpe.PURL) ([]cpe.Candidate, error) {
	select {
	case <-time.After(s.delay):
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *slowCPESource) RequiresNetwork() bool { return false }
func (s *slowCPESource) Priority() int         { return 50 }
