// Package lifecycle enriches OS / runtime Components with release,
// active-support, and end-of-life dates from
// [endoflife.date](https://endoflife.date) — the open-source curated
// catalogue of ~300 popular products (Node, Python, Go, Java,
// Debian, Ubuntu, Alpine, Postgres, MySQL, Redis, Kubernetes, …).
//
// # Why
//
// Compliance teams (especially under EU CRA Article 13) need
// per-Component lifecycle data:
//
//   - Active support window — operators must patch within it
//   - EOL date — production using EOL software is a finding
//   - LTS flag — capacity-planning input
//
// Without it, the SBOM cannot answer "is this component still
// receiving security patches?" — which is the question every
// compliance audit asks.
//
// # Sources
//
// Two-source resolver mirroring the registry enricher pattern
// (S3 Task 4):
//
//   - EndOfLifeSource — fetches `https://endoflife.date/api/<product>.json`
//     through the corporate mirror chain (replace / fallback modes,
//     bearer / basic / header auth, mTLS). Operators with air-gapped
//     environments mirror endoflife.date on internal Artifactory and
//     point Astinus at the mirror via `--mirrors-config`.
//   - BundledSource — embedded JSON snapshot of the most-common
//     products (~12 entries: Node, Python, Go, Java, Debian, Ubuntu,
//     Alpine, Postgres, MySQL, Redis, Kubernetes, Docker). Fallback
//     for `--no-network` runs and for products endoflife.date
//     doesn't cover.
//
// Mode (`--lifecycle-mode`):
//
//   - online — only EndOfLifeSource (no fallback to bundled).
//   - offline — only BundledSource (no network).
//   - hybrid (default) — try online; on miss / transient failure,
//     consult bundled.
//
// # Pipeline placement
//
// Dependencies = `["untracked", "extractor"]` — the lifecycle
// enricher needs the full Component slate (including binary embedded
// deps from S3 Task 1) but doesn't depend on cpe / dedup. Runs
// alongside the registry enricher.
//
// # Output
//
// Per-Component properties (only stamped when a cycle was matched):
//
//	astinus:lifecycle:product           = endoflife product name
//	astinus:lifecycle:cycle             = matched cycle key
//	astinus:lifecycle:release-date      = ISO date (when published)
//	astinus:lifecycle:active-support-end = ISO date (when known)
//	astinus:lifecycle:eol               = ISO date | "true" | "false"
//	astinus:lifecycle:lts               = "true" | "false"
//	astinus:lifecycle:status            = active | maintenance | eol | unknown
//	astinus:lifecycle:days-until-eol    = signed integer (negative = past EOL)
//	astinus:lifecycle:source            = endoflife.date | bundled
//	astinus:lifecycle:fetched-at        = RFC3339 timestamp
//
// The EU CRA validator (S3 Task 2) will consume `status=eol` to
// emit a finding — wired in a follow-up.
//
// ADR-0035.
package lifecycle
