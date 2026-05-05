// Package policy is the extension point for SBOM validation.
//
// Per spec section 8.10, the MVP ships only the interfaces + a tiny
// runner; concrete validators live under `policy/builtin/`. PRSD
// Task 7 lights up the first three concrete validators —
// NTIAValidator (US Executive Order 14028), EUCRAValidator (EU
// Cyber Resilience Act Article 13 + Annex I), and structural
// CycloneDX / SPDX validators that catch the dominant
// missing-required-field shapes without pulling in a JSONSchema
// dependency.
//
// # The Validator interface
//
// One method, `Validate(ctx, *model.SBOM) ([]Finding, error)`. The
// returned findings are written into `sbom.Metadata.Properties` by
// the compliance enricher (see `internal/enrich/compliance`),
// alongside aggregate counts (`astinus:compliance:findings-count`,
// `astinus:compliance:critical-count`, etc.).
//
// # What this package does NOT do
//
// It does not run validators (the enricher does); it does not own
// the Severity → exit-code mapping (that's the CLI's `--fail-on`
// flag); it does not invoke external tools.
package policy
