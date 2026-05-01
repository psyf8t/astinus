// Package version exposes build-time version metadata.
//
// Values are injected at link time via -ldflags "-X". When the binary is
// built without ldflags (e.g. `go run`), defaults below identify a
// development build.
package version

import "fmt"

// These variables are intentionally var (not const) so the linker can
// override them via -X github.com/psyf8t/astinus/internal/version.<Name>=...
var (
	// Version is the semver release string, e.g. "v0.1.0". For
	// untagged builds the Makefile injects a "dev" placeholder.
	Version = "v0.0.0-dev"

	// Commit is the short git SHA, e.g. "bc7514c".
	Commit = "unknown"

	// Date is the build date in RFC3339 form.
	Date = "unknown"
)

// String returns a single-line human-readable version banner.
//
// Format: "astinus <version> (commit <commit>, built <date>)".
func String() string {
	return fmt.Sprintf("astinus %s (commit %s, built %s)", Version, Commit, Date)
}
