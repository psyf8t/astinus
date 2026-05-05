// Package helpers ships the in-process fixtures the Sprint 3
// acceptance suites use: fake HTTP proxy, fake registry mirror
// (npm-style + endoflife.date-style), self-signed CA + client cert
// generator, env var setup/restore, minimal SBOM fixtures.
//
// "In-process" means everything runs inside the test binary via
// `httptest.Server` — no Docker daemon, no real cosign, no real
// public-internet calls. Tests that genuinely need Docker/Syft/
// cosign/grype use the parent `test/acceptance/helpers` package's
// `RequireDockerDaemon` / `RequireCommand` skip helpers.
//
// Build-tag: every Sprint 3 acceptance file carries
// `//go:build acceptance` so the suite ships outside the default
// `go test ./...` run. CI invokes them via `make acceptance` (or
// `go test -tags acceptance ./test/acceptance/sprint3/...`).
//
// ADR-0037.
package helpers
