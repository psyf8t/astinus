package cli

import (
	"strings"
	"testing"

	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestShouldSkipAnonymousNVDInHybrid(t *testing.T) {
	cases := []struct {
		name       string
		mode       cpesources.Mode
		key        string
		components int
		want       bool
	}{
		// Positive cases — S4 Task 4 moved the predicate's trigger
		// from ModeHybrid to ModeAuto. Hybrid now fail-fasts via a
		// separate predicate.
		{"auto + no key + 100 components", cpesources.ModeAuto, "", 100, true},
		{"auto + no key + threshold+1", cpesources.ModeAuto, "", nvdHybridSkipThreshold + 1, true},
		{"auto + no key + 6406 components (real wedge)", cpesources.ModeAuto, "", 6406, true},

		// Boundary — exactly at threshold should NOT trip.
		{"auto + no key + at threshold", cpesources.ModeAuto, "", nvdHybridSkipThreshold, false},

		// Small workload — even rate-limited NVD finishes in tolerable time.
		{"auto + no key + small workload", cpesources.ModeAuto, "", 10, false},

		// Hybrid mode is strict — graceful skip predicate must NOT fire
		// even on huge workloads (the fail-fast predicate handles it).
		{"hybrid + no key + huge workload", cpesources.ModeHybrid, "", 6406, false},
		{"online (alias) + no key + huge workload", cpesources.ModeOnline, "", 6406, false},

		// Operator supplied a key — 10x rate limit, wedge does not happen.
		{"auto + key + huge workload", cpesources.ModeAuto, "set", 6406, false},
		{"hybrid + key + huge workload", cpesources.ModeHybrid, "set", 6406, false},

		// Offline mode — NVD source not added at all in the orchestrator;
		// the predicate is N/A but for safety should also return false.
		{"offline + no key + huge workload", cpesources.ModeOffline, "", 6406, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipAnonymousNVDInHybrid(tc.mode, tc.key, tc.components)
			if got != tc.want {
				t.Errorf("shouldSkipAnonymousNVDInHybrid(%q, key=%q, n=%d) = %v, want %v",
					tc.mode, tc.key, tc.components, got, tc.want)
			}
		})
	}
}

func TestEstimateAnonymousNVDMinutes(t *testing.T) {
	cases := []struct {
		components int
		wantMin    int
	}{
		// 0 → 0 (degenerate).
		{0, 0},
		// 1 component × 6s = 6s → ceil to 1 minute (floor protection).
		{1, 1},
		// 10 × 6s = 60s = 1 minute exact.
		{10, 1},
		// 50 × 6s = 300s = 5 minutes exact.
		{50, 5},
		// 51 × 6s = 306s → ceil to 6 minutes.
		{51, 6},
		// 6406 × 6s = 38436s → ceil to 641 minutes.
		// (Matches the user's reported 168 min hangup at lower hit rate.)
		{6406, 641},
	}
	for _, tc := range cases {
		got := estimateAnonymousNVDMinutes(tc.components)
		if got != tc.wantMin {
			t.Errorf("estimateAnonymousNVDMinutes(%d) = %d, want %d",
				tc.components, got, tc.wantMin)
		}
	}
}

func TestNVDSkipAdviceContainsActionableHints(t *testing.T) {
	got := nvdSkipAdvice(6406)
	for _, want := range []string{
		"NVD API rate limit",
		"5 req/30s",
		"6406 components",
		"Skipping NVD API source",
		"NVD_API_KEY",
		"https://nvd.nist.gov/developers/request-an-api-key",
		// S4 Task 4: graceful-skip advice now points at hybrid for
		// callers who want the strict variant.
		"--cpe-mode hybrid",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("advice missing %q\nfull message: %s", want, got)
		}
	}
}

// TestNVDFailFastAdviceContainsActionableHints covers the strict
// counterpart wrapped in the exit-60 error. S4 Task 4.
func TestNVDFailFastAdviceContainsActionableHints(t *testing.T) {
	got := nvdFailFastAdvice(6406)
	for _, want := range []string{
		"cpe-mode=hybrid",
		"NVD_API_KEY",
		"--cpe-mode=auto",
		"--cpe-mode=offline",
		"5 req/30s",
		"6406 components",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fail-fast advice missing %q\nfull message: %s", want, got)
		}
	}
}

// TestStampCPEModeMetadata covers the SBOM-metadata stamp helper
// that lets downstream SBOM consumers tell apart full-online runs
// from auto-degraded / offline / disabled runs. S4 Task 4 +
// S5 Task 4 finalised the contract: mode + sources-used +
// sources-skipped (with `<source>:<reason>` for the latter).
func TestStampCPEModeMetadata(t *testing.T) {
	t.Run("auto with skipped sources", func(t *testing.T) {
		sbom := &model.SBOM{}
		opts := &enrichOptions{
			cpeMode:          "auto",
			cpeModeEffective: "auto",
			cpeUsedSources: []string{
				"pattern-matcher", "clearly-defined", "heuristic",
			},
			cpeSkippedSources: []string{"online-nvd:no-NVD_API_KEY"},
		}
		stampCPEModeMetadata(sbom, opts)
		if got := sbom.Metadata.Properties[model.PropertyCPEMode]; got != "auto" {
			t.Errorf("PropertyCPEMode = %q, want auto", got)
		}
		want := "pattern-matcher,clearly-defined,heuristic"
		if got := sbom.Metadata.Properties[model.PropertyCPESourcesUsed]; got != want {
			t.Errorf("PropertyCPESourcesUsed = %q, want %q", got, want)
		}
		if got := sbom.Metadata.Properties[model.PropertyCPESourcesSkipped]; got != "online-nvd:no-NVD_API_KEY" {
			t.Errorf("PropertyCPESourcesSkipped = %q, want online-nvd:no-NVD_API_KEY", got)
		}
	})
	t.Run("hybrid full-online", func(t *testing.T) {
		sbom := &model.SBOM{}
		opts := &enrichOptions{
			cpeMode:          "hybrid",
			cpeModeEffective: "hybrid",
			cpeUsedSources: []string{
				"pattern-matcher", "online-nvd", "clearly-defined", "heuristic",
			},
		}
		stampCPEModeMetadata(sbom, opts)
		if got := sbom.Metadata.Properties[model.PropertyCPEMode]; got != "hybrid" {
			t.Errorf("PropertyCPEMode = %q, want hybrid", got)
		}
		if _, present := sbom.Metadata.Properties[model.PropertyCPESourcesSkipped]; present {
			t.Errorf("PropertyCPESourcesSkipped should be absent when no skip happened")
		}
		want := "pattern-matcher,online-nvd,clearly-defined,heuristic"
		if got := sbom.Metadata.Properties[model.PropertyCPESourcesUsed]; got != want {
			t.Errorf("PropertyCPESourcesUsed = %q, want %q", got, want)
		}
	})
	t.Run("offline records online sources as skipped", func(t *testing.T) {
		sbom := &model.SBOM{}
		opts := &enrichOptions{
			cpeMode:          "offline",
			cpeModeEffective: "offline",
			cpeUsedSources:   []string{"pattern-matcher", "heuristic"},
			cpeSkippedSources: []string{
				"online-nvd:offline-mode",
				"clearly-defined:offline-mode",
			},
		}
		stampCPEModeMetadata(sbom, opts)
		if got := sbom.Metadata.Properties[model.PropertyCPEMode]; got != "offline" {
			t.Errorf("PropertyCPEMode = %q, want offline", got)
		}
		// Reason-encoded skipped entries surface the offline mode.
		skipped := sbom.Metadata.Properties[model.PropertyCPESourcesSkipped]
		if !strings.Contains(skipped, "online-nvd:offline-mode") {
			t.Errorf("PropertyCPESourcesSkipped = %q, want online-nvd:offline-mode entry", skipped)
		}
	})
	t.Run("nil opts is no-op", func(t *testing.T) {
		sbom := &model.SBOM{}
		stampCPEModeMetadata(sbom, nil)
		if len(sbom.Metadata.Properties) != 0 {
			t.Errorf("expected empty properties on nil opts, got %v",
				sbom.Metadata.Properties)
		}
	})
}

// TestShouldFailFastOnAnonymousNVDInHybrid pins the strict
// counterpart predicate added by S4 Task 4. Mirror cases of the
// graceful skip matrix above; the predicate fires under
// ModeHybrid / ModeOnline (strict) without an API key on workloads
// above the threshold.
func TestShouldFailFastOnAnonymousNVDInHybrid(t *testing.T) {
	cases := []struct {
		name       string
		mode       cpesources.Mode
		key        string
		components int
		want       bool
	}{
		{"hybrid + no key + above threshold", cpesources.ModeHybrid, "", nvdHybridSkipThreshold + 1, true},
		{"online (alias) + no key + above", cpesources.ModeOnline, "", 6406, true},
		{"hybrid + no key + at threshold", cpesources.ModeHybrid, "", nvdHybridSkipThreshold, false},
		{"hybrid + no key + small workload", cpesources.ModeHybrid, "", 10, false},
		{"hybrid + key + above", cpesources.ModeHybrid, "set", 6406, false},
		{"auto + no key + above", cpesources.ModeAuto, "", 6406, false},
		{"offline + no key + above", cpesources.ModeOffline, "", 6406, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldFailFastOnAnonymousNVDInHybrid(tc.mode, tc.key, tc.components)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
