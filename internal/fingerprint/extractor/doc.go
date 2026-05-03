// Package extractor identifies a binary or archive's upstream
// package by reading format-specific metadata embedded in the file.
//
// # Why this exists
//
// The Stage 4 untracked enricher classifies files into broad
// categories (executable / library / archive / script) and emits a
// Component with name = basename. That gets the file into the SBOM
// but leaves it without the version + PURL the CPE enricher needs to
// match a CVE. After Hardening Sprint #1 untracked binaries had 0 %
// PURL coverage on the reference image — Grype / OSV / Trivy
// couldn't pin them to a known package.
//
// Multi-modal extraction reads the strongest signal available per
// format:
//
//   - Go binaries — `debug/buildinfo` recovers main module + every
//     dependency's name + version (full transitive graph).
//   - Rust binaries built with `cargo auditable` — the `.dep-v0`
//     ELF section is a zlib-compressed JSON list of every Cargo
//     package linked in.
//   - JAR / WAR / EAR — `META-INF/maven/.../pom.properties` is
//     authoritative; falls back to MANIFEST.MF, then to filename
//     pattern parsing.
//   - Python wheels — `*.dist-info/METADATA` is RFC 822 with Name +
//     Version headers.
//   - ELF libraries — SONAME from .dynamic section + GNU build-id
//     from .note.gnu.build-id give a name + a content fingerprint
//     even when no language-specific signal is present.
//   - PE binaries — minimal: today the extractor only fingerprints
//     "this is a PE" and falls back to filename versioning.
//     Full VERSIONINFO resource parsing is documented as deferred
//     (container images are overwhelmingly Linux; the ROI on PE
//     extraction is small).
//
// # Architecture
//
// The Extractor interface has Match (cheap header / filename check)
// and Extract (parse + return Identity). The Registry runs every
// matching extractor in registration order, then returns the
// resulting Identities sorted by confidence descending.
//
// # In-memory contract
//
// Extractors take a File{Path, Body} where Body is already
// in-memory bytes — Astinus reads tar entries via
// `layer.WalkFiles`, which delivers each file's bytes once. The
// extractors do NOT touch the local filesystem; they re-wrap the
// body as a `*bytes.Reader` when an stdlib API expects
// `io.ReaderAt` (Go buildinfo, ELF, PE, ZIP).
//
// # What this package does NOT do
//
// It does not allocate disk; it does not pull blobs from the
// registry; it does not invoke external commands. Its only side
// effect is reading bytes the caller already provided.
package extractor
