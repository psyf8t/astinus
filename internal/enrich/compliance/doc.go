// Package compliance is the enrich.Enricher that runs every
// registered policy.Validator (NTIA, EU CRA, CycloneDX-structural,
// SPDX-structural by default) and stamps findings onto the SBOM.
//
// The enricher does NOT abort the pipeline on findings — that's
// the CLI's `--fail-on` flag (see `internal/cli/enrich.go`). The
// enricher's job is to make findings discoverable in the rendered
// output:
//
//   - SBOM-level: `astinus:compliance:findings-count`,
//     `astinus:compliance:critical-count`, … on
//     `Metadata.Properties` so a downstream consumer reading the
//     SBOM can tell at a glance.
//   - Per-validator: `astinus:compliance:<validator-name>:status`
//     = `passed` / `passed-with-warnings` / `failed`.
//   - Per-Component: `astinus:compliance:finding:<rule-id>` =
//     `<severity>` so vuln-scanner / dashboard consumers can
//     correlate the finding back to the offending component.
//
// # Pipeline position
//
// Declares `Dependencies() = []string{"dedup"}` so it runs after
// the SBOM is finalized — validators see the post-dedup component
// set, with PURLs / CPEs / Origin all in place.
//
// # Validator registration
//
// `New()` returns an Enricher with the bundled-default validator
// set (NTIA, EU CRA, CycloneDX-structural, SPDX-structural).
// `NewWithValidators(...)` lets callers override (tests, future
// CLI flags that disable individual validators).
package compliance
