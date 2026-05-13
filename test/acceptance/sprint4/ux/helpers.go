//go:build acceptance

package ux

import (
	"os"
	"testing"
)

// minimalEnv returns an environment suitable for running the
// astinus binary in tests that need a guaranteed absence of
// specific env vars (NVD_API_KEY for the hybrid fail-fast test,
// proxies, etc.). We keep PATH (so subprocess lookups work),
// HOME, and TMPDIR — every other variable is stripped. S4 Task 7.
func minimalEnv(tb testing.TB) []string {
	tb.Helper()
	pass := []string{"PATH", "HOME", "TMPDIR"}
	out := make([]string, 0, len(pass))
	for _, k := range pass {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}
