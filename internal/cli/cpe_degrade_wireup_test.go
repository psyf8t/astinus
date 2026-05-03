package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/telemetry"
)

// TestBuildCPEEnricherSkipsNVDInLargeHybridWorkload is the wire-up
// test for the CPE rate-limit graceful-degradation policy
// (ADR-0028). The predicate test (cpe_degrade_test.go) covers the
// decision matrix; this test asserts buildCPEEnricher actually
// honours the predicate by:
//
//   - emitting the EventCPENVDSkipped warning, AND
//   - omitting the NVD source from the resolver chain.
func TestBuildCPEEnricherSkipsNVDInLargeHybridWorkload(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	enr, err := buildCPEEnricher(
		&enrichOptions{cpeMode: "hybrid"},
		nil, logger,
		nvdHybridSkipThreshold+1, // above the threshold
	)
	if err != nil {
		t.Fatalf("buildCPEEnricher: %v", err)
	}
	if enr == nil {
		t.Fatal("enricher must not be nil")
	}

	out := logBuf.String()
	if !strings.Contains(out, telemetry.EventCPENVDSkipped) {
		t.Errorf("expected %q in log, got:\n%s", telemetry.EventCPENVDSkipped, out)
	}
	for _, want := range []string{
		"NVD_API_KEY",
		"--cpe-mode online",
		"5 req/30s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to mention %q, got:\n%s", want, out)
		}
	}
}

// TestBuildCPEEnricherKeepsNVDBelowThreshold asserts the converse:
// for small hybrid workloads, the NVD source stays in the chain
// (no degradation, no warning).
func TestBuildCPEEnricherKeepsNVDBelowThreshold(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	enr, err := buildCPEEnricher(
		&enrichOptions{cpeMode: "hybrid"},
		nil, logger,
		nvdHybridSkipThreshold, // exactly at threshold; must NOT skip
	)
	if err != nil {
		t.Fatalf("buildCPEEnricher: %v", err)
	}
	if enr == nil {
		t.Fatal("enricher must not be nil")
	}
	if strings.Contains(logBuf.String(), telemetry.EventCPENVDSkipped) {
		t.Errorf("did not expect %q at threshold, got:\n%s",
			telemetry.EventCPENVDSkipped, logBuf.String())
	}
}

// TestBuildCPEEnricherKeepsNVDInOnlineMode confirms `--cpe-mode online`
// is never second-guessed even on huge workloads — operators who
// asked for network get network.
func TestBuildCPEEnricherKeepsNVDInOnlineMode(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := buildCPEEnricher(
		&enrichOptions{cpeMode: string(cpesources.ModeOnline)},
		nil, logger,
		6406, // user's reported huge workload
	)
	if err != nil {
		t.Fatalf("buildCPEEnricher: %v", err)
	}
	if strings.Contains(logBuf.String(), telemetry.EventCPENVDSkipped) {
		t.Errorf("online mode must not trigger NVD skip, got:\n%s", logBuf.String())
	}
}

// TestBuildCPEEnricherKeepsNVDWithAPIKey asserts that supplying an
// API key via env disables the degradation regardless of workload —
// the 10× rate avoids the wedge.
func TestBuildCPEEnricherKeepsNVDWithAPIKey(t *testing.T) {
	t.Setenv("NVD_API_KEY", "secret")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := buildCPEEnricher(
		&enrichOptions{cpeMode: "hybrid"},
		nil, logger,
		6406,
	)
	if err != nil {
		t.Fatalf("buildCPEEnricher: %v", err)
	}
	if strings.Contains(logBuf.String(), telemetry.EventCPENVDSkipped) {
		t.Errorf("authenticated NVD must not be skipped, got:\n%s", logBuf.String())
	}
}
