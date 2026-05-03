// Package helpers contains the shared scaffolding for Astinus's
// acceptance test suite (PRSD-Task-9).
//
// Design intent:
//
//   - The acceptance suite invokes external tooling (docker, syft,
//     grype, …) via os/exec rather than pulling in vendor SDKs.
//     Same in-tree-where-bounded precedent as PRSD-Task-1..8 — the
//     suite is a CI-side harness, not a runtime dependency, so we
//     do not want to inflate the production binary's dep tree.
//   - Every test that requires an external tool calls a Require*
//     helper that t.Skip()s when the tool is unavailable, so the
//     suite degrades gracefully on developer machines that don't
//     have the full toolchain installed. The CI workflow
//     (.github/workflows/acceptance.yml) installs the prereqs and
//     fails the build when expected runs are skipped.
//   - SBOM probes (NTIA findings, coverage ratios, runtime
//     property, dup count, hasComponent / findComponent) read the
//     canonical CycloneDX output. The probes deliberately tolerate
//     both the `name`/`version` style and the `bom-ref` style so
//     they can target any reasonable Astinus output shape.
//
// All files in this package are buildable in any context (no build
// tags), so `go vet ./...` covers them; the consumer test files
// gate themselves with `//go:build acceptance` or
// `//go:build benchmark`.
package helpers
