// Package sources hosts one Source implementation per supported
// package ecosystem. Each file contains exactly one Source —
// shared helpers live in the parent registry package.
//
// Sprint 3 Task 4 implementations:
//
//   - npm.go      — full (npmjs.org / Verdaccio / Artifactory)
//   - pypi.go     — full (pypi.org JSON API)
//   - maven.go    — full (search.maven.org / Maven Central / Artifactory)
//   - golang.go   — full (proxy.golang.org / private GOPROXY)
//
// Stub Sources (registered, return ErrNotFound; documented as
// follow-up):
//
//   - cargo.go, gem.go, nuget.go, deb.go, alpine.go,
//     repology.go, ecosyste-ms.go
//
// ADR-0033 §4 documents the per-source dispatch table.
package sources
