package enrich

import "github.com/psyf8t/astinus/internal/version"

// currentVersion isolates the version-package import so tests can
// substitute it without touching package-level state. (Today the
// substitution would cross packages anyway; the indirection exists
// so the read site stays in one place if we ever need to change it.)
func currentVersion() string {
	return version.Version
}
