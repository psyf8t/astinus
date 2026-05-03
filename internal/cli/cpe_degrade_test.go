package cli

import (
	"strings"
	"testing"

	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
)

func TestShouldSkipAnonymousNVDInHybrid(t *testing.T) {
	cases := []struct {
		name       string
		mode       cpesources.Mode
		key        string
		components int
		want       bool
	}{
		// Positive case — the bug from the user report.
		{"hybrid + no key + 100 components", cpesources.ModeHybrid, "", 100, true},
		{"hybrid + no key + threshold+1", cpesources.ModeHybrid, "", nvdHybridSkipThreshold + 1, true},
		{"hybrid + no key + 6406 components (real wedge)", cpesources.ModeHybrid, "", 6406, true},

		// Boundary — exactly at threshold should NOT trip.
		{"hybrid + no key + at threshold", cpesources.ModeHybrid, "", nvdHybridSkipThreshold, false},

		// Small workload — even rate-limited NVD finishes in tolerable time.
		{"hybrid + no key + small workload", cpesources.ModeHybrid, "", 10, false},

		// Operator explicitly chose online — never second-guess them.
		{"online + no key + huge workload", cpesources.ModeOnline, "", 6406, false},

		// Operator supplied a key — 10x rate limit, wedge does not happen.
		{"hybrid + key + huge workload", cpesources.ModeHybrid, "set", 6406, false},
		{"online + key + huge workload", cpesources.ModeOnline, "set", 6406, false},

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
		"--cpe-mode online",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("advice missing %q\nfull message: %s", want, got)
		}
	}
}
