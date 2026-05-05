// Package contenthash classifies a target image's components against
// a base image by file content hash, not by file path.
//
// # Why this exists
//
// The Stage 5 / Hardening-Sprint #1 base diff matches by layer prefix
// (cheap, accurate) and falls back to path matching when layer
// digests diverge — which they do for every multi-stage build. The
// `--from=builder COPY x /` pattern moves a file from a builder
// stage into the final image; the file's path AND its containing
// layer change, but its bytes do not. Path matching reports it as
// "app"; the operator sees Origin=app for code that is unmodified
// from upstream.
//
// Content-addressable diffing fixes this. It hashes every visible
// file in the base image into a BaseSet (SHA-256 → first-seen
// path/layer evidence), then asks for each target component:
// "do any of your file paths in the target image hash to something
// the base image also has?" If yes → Origin=base, with the matching
// base path stamped as forensic evidence. The match works regardless
// of layer prefix, regardless of squashing.
//
// # What this package provides
//
//   - BaseSet         — bloom-filter-fronted hash → Evidence index.
//   - HashStream      — constant-memory streaming SHA-256.
//   - HashCache       — per-scan path → hash cache.
//   - BuildBaseSet    — walks a v1.Image's visible files, populates
//     a BaseSet.
//   - ScanTarget      — walks a v1.Image and returns path → hash
//     for every visible file.
//
// # What this package does NOT do
//
// It does not extract the base image or write tar files. It does not
// touch the SBOM model — the caller (basediff enricher) decides how
// to translate hash matches into Origin / properties.
//
// # Bloom filter rationale
//
// The exact map is sufficient for correctness; the bloom filter exists
// so a typical `target_files >> base_overlap` workload pays a few
// nanoseconds for the negative case instead of a full hash-table
// probe. We implemented the bloom in-tree (~70 LOC) rather than pull
// in github.com/bits-and-blooms/bloom/v3, which would bring 2 extra
// transitive deps (bitset + murmur3) for an algorithm whose math is
// well-known and exhaustively testable. See ADR-0020 for the
// trade-off.
package contenthash
