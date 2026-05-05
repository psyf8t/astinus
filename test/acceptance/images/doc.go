// Package images holds the per-image-type acceptance tests for
// PRSD-Task-9.
//
// Each test:
//
//  1. Builds a self-contained image via the helpers/docker.go
//     wrappers (no external registry pulls beyond the base layer
//     pull docker would do anyway).
//  2. Generates a baseline SBOM via syft (skipped when syft is
//     not installed).
//  3. Runs the locally-built astinus binary against the pair.
//  4. Asserts the Track A / B / C gates the spec calls for.
//
// Every test gates itself with `t.Skip` via RequireDockerDaemon
// (and the per-runtime helpers do the same), so the suite degrades
// gracefully on machines without the full toolchain. The CI
// workflow installs the prereqs and turns missing tools into
// failures via -run filters.
//
// The whole package is built only under `//go:build acceptance`
// so default `go test ./...` does NOT execute these tests.
package images
