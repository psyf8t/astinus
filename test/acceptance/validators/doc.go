// Package validators holds the external SBOM-validator integration
// tests for PRSD-Task-9 (`cyclonedx-cli`, `pyspdxtools`, `bomctl`).
// Every test gates itself with `helpers.RequireCommand` so the
// suite degrades gracefully when a validator is not installed.
//
// Built only under `//go:build acceptance`.
package validators
