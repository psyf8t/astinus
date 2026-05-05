//go:build acceptance

package helpers

import (
	"os"
	"testing"
)

// SetEnv sets an env var for the test and restores the prior value
// (or unsets if the var was unset) on cleanup. Same shape as
// `t.Setenv` but works on TB so helpers in this package can take
// either *testing.T or *testing.B.
//
// Acceptance tests fan out across goroutines (httptest servers run
// their own); env mutation needs to happen before any goroutine
// reads the var. Tests should call SetEnv before NewFakeProxy /
// before constructing Astinus configs.
func SetEnv(tb testing.TB, key, value string) {
	tb.Helper()
	prev, hadPrev := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		tb.Fatalf("setenv %s: %v", key, err)
	}
	tb.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// UnsetEnv unsets an env var for the test and restores the prior
// value (if any) on cleanup. Used by air-gapped tests that need
// HTTPS_PROXY explicitly cleared even when the host shell sets it.
func UnsetEnv(tb testing.TB, key string) {
	tb.Helper()
	prev, hadPrev := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		tb.Fatalf("unsetenv %s: %v", key, err)
	}
	tb.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(key, prev)
		}
	})
}
