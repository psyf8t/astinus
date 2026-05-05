// Package extractor is the standalone enricher that lifts embedded
// module / crate / package dependencies out of binary components into
// top-level SBOM components plus dependency edges.
//
// # Why a separate enricher
//
// The Stage-4 untracked enricher already runs the multi-modal
// extractor registry (`internal/fingerprint/extractor`) — but only on
// binaries that the untracked walker discovered itself. Binaries
// already populated by the upstream SBOM (typical: Syft tags
// `/usr/local/bin/yq` as a `go-module-binary` Component, with file
// path in Evidence.Locations) skip the untracked path entirely
// because their owning location is in the "known paths" index. The
// extractor never sees them, so embedded dependencies (`gopkg.in/
// yaml.v3`, `golang.org/x/net`, …) never make it to the SBOM.
//
// This package closes that gap: a separate pipeline stage that walks
// every Component with a binary file location, runs the extractor
// registry over the underlying bytes, and projects each extracted
// dependency as:
//
//   - a top-level model.Component (deduplicated by PURL across all
//     parents, so the same `golang.org/x/net@v0.10.0` referenced by
//     yq AND grype appears exactly once);
//   - a model.Relationship edge `parent_BOMRef → dep_BOMRef`
//     (Type = RelationshipDependsOn) so the CycloneDX writer emits
//     the canonical `dependencies` graph and SPDX writes
//     `DEPENDS_ON` relationships.
//
// # Pipeline placement
//
// Dependencies declared as `["untracked"]` so the topological sorter
// runs us after the untracked walker has had its turn. The cpe and
// dedup enrichers gain `"extractor"` in their Dependencies() so the
// extracted top-level components also pick up CPEs and feed into the
// dedup pass.
//
// # Sprint 3 Task 0 / Task 1 cross-reference
//
// Task 0 (CPE confidence) refines per-component CPE quality. Task 1
// (this package) widens the input set: previously we had ~6000
// PURL'd components, now each Go/Rust/Java binary brings its full
// embedded module graph — yq alone adds 10+ subcomponents. ADR-0030.
package extractor
