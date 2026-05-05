// Package registry enriches Components with metadata fetched from
// package registries (npm, PyPI, Maven, cargo, gem, NuGet, golang
// proxy, deb, alpine) plus aggregator services (Repology,
// ecosyste.ms).
//
// # Why
//
// Syft fills name + version + PURL on most Components but rarely
// fills licenses, supplier, homepage, or repository URL. The v0.2
// reference image had:
//
//   - 18.8% of Components with licenses
//   - ~0% with supplier
//   - ~0% with homepage
//   - ~0% with repository URL
//
// That's not enough to satisfy NTIA Element 1 (Supplier) or to drive
// license-compliance audits. The fields are available from each
// ecosystem's package registry — this enricher fetches and projects
// them.
//
// # Corporate environment
//
// Astinus runs inside enterprises where outbound traffic to public
// registries is blocked and internal Artifactory / Nexus / JFrog /
// Verdaccio mirrors are mandatory. Each Source supports:
//
//   - Mirror configuration (`MirrorModeReplace` for air-gapped;
//     `MirrorModeFallback` for hybrid).
//   - Authentication (bearer / basic / custom header) with secrets
//     read from env vars at request time.
//   - mTLS client certificates.
//   - Custom CA bundles (corporate root CA).
//   - HTTP / HTTPS proxy via `http.ProxyFromEnvironment`.
//   - Per-mirror rate limiting.
//
// `--no-network` and `--no-registry` disable the enricher entirely.
//
// # Pipeline placement
//
// `Dependencies()` returns `["untracked", "extractor"]` so registry
// enrichment runs after the discovery / extraction stages have
// produced the full Component slate (including binary embedded
// deps from S3 Task 1) but before `cpe` / `dedup` so the registry-
// derived metadata participates in CPE matching and the dedup key.
//
// # Scope (Sprint 3 Task 4)
//
// Implemented in this iteration:
//
//   - Architecture: Source interface, Resolver, Cache (memory + on-disk),
//     mirror config schema, auth applier (bearer/basic/header),
//     per-mirror transport builder (mTLS), CLI flags.
//   - Sources: npm, pypi, maven, golang — fully implemented with
//     license normalisation and field projection.
//   - Sources: cargo, gem, nuget, deb, alpine, repology,
//     ecosyste-ms — registered stubs that return ErrNotFound.
//     Source-specific fetch logic deferred to a follow-up; the
//     stubs preserve the API surface so adding them is one file
//     change each.
//
// ADR-0033 (architecture) + ADR-0034 (corporate mirror support).
package registry
