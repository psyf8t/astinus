package cli

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/telemetry"
)

// TestBuildCPEEnricherSkipsNVDInLargeAutoWorkload is the wire-up
// test for the CPE rate-limit graceful-degradation policy
// (ADR-0028 + ADR-0043). S4 Task 4 moved the predicate's trigger
// from ModeHybrid → ModeAuto. The predicate test
// (cpe_degrade_test.go) covers the decision matrix; this test
// asserts buildCPEEnricher honours the predicate by:
//
//   - emitting the EventCPENVDSkipped warning, AND
//   - omitting the NVD source from the resolver chain, AND
//   - recording "online-nvd" in opts.cpeSkippedSources.
func TestBuildCPEEnricherSkipsNVDInLargeHybridWorkload(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := &enrichOptions{cpeMode: "auto"}
	enr, err := buildCPEEnricher(
		opts,
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
		"--cpe-mode hybrid",
		"5 req/30s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to mention %q, got:\n%s", want, out)
		}
	}
	// S5 Task 4 finalised the format: entries are
	// `<source>:<reason>` so SBOM consumers can distinguish
	// graceful-skip from offline-mode from configuration choices.
	wantSkipped := []string{"online-nvd:no-NVD_API_KEY"}
	if !equalStringSlice(opts.cpeSkippedSources, wantSkipped) {
		t.Errorf("opts.cpeSkippedSources = %v, want %v",
			opts.cpeSkippedSources, wantSkipped)
	}
	if opts.cpeModeEffective != "auto" {
		t.Errorf("opts.cpeModeEffective = %q, want auto", opts.cpeModeEffective)
	}
}

// TestBuildCPEEnricherKeepsNVDBelowThreshold asserts the converse:
// for small auto-mode workloads, the NVD source stays in the chain
// (no degradation, no warning).
func TestBuildCPEEnricherKeepsNVDBelowThreshold(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	enr, err := buildCPEEnricher(
		&enrichOptions{cpeMode: "auto"},
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

// TestBuildCPEEnricherFailsFastInHybridWithoutAPIKey — S4 Task 4:
// the strict variant (`--cpe-mode hybrid`) refuses to run when NVD
// would be effectively unreachable under anonymous rate limits.
// Exit code is wired by newExitError(ExitCPESourceUnavailable, ...).
func TestBuildCPEEnricherFailsFastInHybridWithoutAPIKey(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	enr, err := buildCPEEnricher(
		&enrichOptions{cpeMode: "hybrid"},
		nil, logger,
		nvdHybridSkipThreshold+1,
	)
	if err == nil {
		t.Fatalf("expected fail-fast error, got nil; enr=%v", enr)
	}
	var exitErr *exitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exitError, got %T: %v", err, err)
	}
	if exitErr.code != ExitCPESourceUnavailable {
		t.Errorf("exit code = %d, want %d", exitErr.code, ExitCPESourceUnavailable)
	}
	for _, want := range []string{
		"NVD_API_KEY",
		"--cpe-mode=auto",
		"--cpe-mode=offline",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q, got:\n%s", want, err.Error())
		}
	}
}

// TestBuildCPEEnricherOnlineAliasWarns confirms `--cpe-mode online`
// emits a deprecation warning and behaves as hybrid (fail-fast on
// rate-limit hazard).
func TestBuildCPEEnricherOnlineAliasWarns(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := buildCPEEnricher(
		&enrichOptions{cpeMode: string(cpesources.ModeOnline)},
		nil, logger,
		6406,
	)
	if err == nil {
		t.Fatal("expected fail-fast error under online alias")
	}
	if !strings.Contains(logBuf.String(), "cpe.mode.deprecated") {
		t.Errorf("expected cpe.mode.deprecated log; got:\n%s", logBuf.String())
	}
}

// equalStringSlice — local helper so this test file doesn't pull in
// an extra dep.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
