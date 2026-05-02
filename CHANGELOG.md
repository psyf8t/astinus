# Changelog

All notable post-stage fixes that change observable behaviour. Stage
deliverables themselves are tracked in the implementation log; this
file is for cross-stage fixes that an operator might bisect against.

## Unreleased

### Changed

- CPE enricher now ALWAYS runs the resolver chain when a PURL is
  present, even on components that already carry a CPE. Syft
  populates every component with a placeholder
  `vendor=name, product=name` CPE that almost never matches NVD's
  authoritative entries; the enricher previously bailed at
  `if len(c.CPEs) > 0 { ... return }`, leaving 0 added CPEs in
  production output. Now Astinus's bundled (high-confidence) /
  heuristic (low-confidence) CPE is appended alongside the
  pre-existing one. New `cpe.complete` log line surfaces the
  per-run breakdown (`components_examined`, `had_cpe_already`,
  `added_cpe`, `validated`, `no_match`, `no_purl`, `purl_error`).
  On the real ~533 MiB benchmark image: **273 of 753 PURL'd
  components (36 %) now get an authoritative Astinus CPE — 28
  high-confidence bundled, 245 heuristic.**
  (post-Stage-13 hardening Task 5.1 + 5.3)
- Bundled CPE mapping extended from ~57 → ~91 entries with
  high-frequency debian packages (libc6, libssl3, libcurl4,
  openssh, sudo, perl, perl-base, python3, gnupg, git, wget, tar,
  gzip, coreutils, dpkg, apt, imagemagick, vim, nano, libxml2,
  libsqlite3-0, zlib1g, ca-certificates), more npm (yargs, json5,
  jquery, jsonwebtoken, passport, semver, ip, follow-redirects,
  node-forge, fast-xml-parser, ejs, ssri, etc.), more rpm/apk
  variants. (post-Stage-13 hardening Task 5.2)
- basediff fallback mode now matches paths even on components with
  no `LayerInfo`. Previously the enricher early-returned
  `Origin=unknown` for any component without `LayerInfo`, which is
  most of what Syft produces (Stage 3 attribution rarely stamps
  Syft components). The fallback path-matcher now also reads file
  paths from `syft:location:N:path` properties (not just
  `Evidence.Locations`). On real Syft input every Origin slot
  used to be `unknown`; with this fix path-based base/app
  classification works without LayerInfo.
  (post-Stage-13 hardening Task 3.1)
- basediff downgrade emits a structured `basediff.fallback` warn
  log with `reason`, `base_ref`, optional `error`, and `advice`
  fields. Reasons cover `no-base-label`, `base-resolve-failed`,
  `no-base-ref`, `base-pull-failed`, `compute-diff-failed`,
  `layer-prefix-mismatch`. The `advice` field tells the operator
  how to fix it (rebuild with the label, pre-pull the base, pass
  `--base <ref>`). (post-Stage-13 hardening Task 3.2)

### Added

- New `dedup` enricher (`internal/enrich/dedup`) runs as the
  pipeline finalize stage and merges duplicate components. Keys
  by priority: PURL > CPE > SHA-256 > name+version+type.
  Components with no identifying signal pass through unchanged
  (two `name="config.txt"` components without versions are NOT
  assumed identical). Merge is union of evidence locations,
  hashes, licenses, CPEs, and properties (primary wins on
  property conflict; secondary value preserved as
  `astinus:dedup:conflict:<key>` breadcrumb). Primary chosen by
  identification strength (PURL beats no-PURL; more
  Evidence.Locations beats fewer; original-order-earliest as
  tiebreaker). On a real ~533 MiB Node.js+Debian image: 8 923 →
  6 608 components in 8 ms. (post-Stage-13 hardening Task 2)
- New `ModePartial` for basediff. When the base image reference is
  known (label or explicit) but the base image cannot be opened
  (typical: `docker pull` not yet run, no daemon copy, network
  refused), the enricher falls back to a heuristic — "every layer
  except the last is base" — and stamps every component
  `astinus:basediff:confidence=low` so the consumer can tell. The
  prior failure mode was a complete `Origin=unknown` shutdown.
  (post-Stage-13 hardening Task 3.3)

- Untracked enricher now skips files that belong to packages already
  in the SBOM. Reads file paths from BOTH `Component.Evidence.Locations`
  AND Syft's `syft:location:N:path` properties (Syft does not populate
  `evidence.occurrences`, so the previous implementation was blind to
  every file Syft already covered). Derives package roots from
  per-ecosystem manifest files (`package.json`, `setup.py`, `go.mod`,
  `Cargo.toml`, `pom.xml`, `Gemfile`, `composer.json`, `METADATA`,
  `PKG-INFO`, `control`, `*.gemspec`) and drops every file under any
  derived root. New `--include-redundant` flag opts back in for debug.
  On a real ~1 GB Node.js+Debian image this drops 9 302 untracked
  components ≥ 90% (post-Stage-13 hardening Task 1.1).
- Untracked enricher now skips files whose basename or extension marks
  them as documentation / source / debug-symbol noise (LICENSE, README,
  COPYING, AUTHORS, CHANGELOG, *.h, *.cpp, *.map, *.d.ts, *.asc, …).
  New `--include-noise` flag opts back in for debug. Library / archive
  / executable extensions (`.so`, `.dll`, `.jar`, `.dylib`) are
  deliberately NOT in the catalog — they ARE components.
  (post-Stage-13 hardening Task 1.2)
- Untracked enricher emits a `untracked.stats` log line at the end of
  every scan with `files_scanned`, `files_added`, `files_skipped_*`
  counters per category and throughput.
  (post-Stage-13 hardening Task 1.3)

### Security

- Bumped Go toolchain floor from 1.25.0 to 1.25.9. The previous floor
  exposed 19 known stdlib CVEs reported by `govulncheck` (notably
  `GO-2025-4007/4008/4009` reachable via the registry-pull TLS
  handshake). Builders that have only an older local toolchain will
  auto-download 1.25.9 via `GOTOOLCHAIN=auto`. Dockerfile builder
  pinned to `golang:1.25.9-alpine` for reproducibility. The Makefile
  now exports `GOTOOLCHAIN` from the `go` directive so all `go`
  invocations agree on a version. (post-stage-13 review F-001)

### Added

- Fuzz targets for the five hand-rolled parsers: `FuzzDetectBytes`,
  `FuzzReadJSON` (CycloneDX), `FuzzReadJSON` + `FuzzReadTagValue`
  (SPDX), `FuzzReadGoBuildInfo`. Seeded from existing fixtures plus
  crafted edge cases (BOMs, truncations, magic-byte stubs). The
  contract is "must not panic"; every fuzz seed runs as part of the
  regular test suite. Discovered and fixed one real nil-pointer
  panic in the SPDX mapper (see Fixed below). (post-stage-13 review F-006)

### Changed

- ClearlyDefined dropped from the default matcher chain. Per
  ADR-0015 §7 the Stage-13 ClearlyDefined matcher was a
  coordinate-indexed stub that always returned `ErrNoMatch`;
  wiring it cost a cache+rate-limit hop per lookup for nothing.
  The matcher type stays in the package so a future PURL-based
  resolver in the cpe chain can inhabit the slot.
  (post-stage-13 review F-012)

### Fixed

- SWH HTTP response body capped at 1 MiB before JSON decode
  (`io.LimitReader`). Defensive against a hostile / misconfigured
  intermediary returning a giant body. Real SWH responses are a
  few KB. (post-stage-13 review F-017)
- Software Heritage and ClearlyDefined matcher HTTP clients now
  share the same `transport.New(...)` `http.RoundTripper` as the
  registry source, inheriting the corporate CA bundle (`--ca-cert`),
  mTLS client cert, retry policy, and `astinus/<version>` User-Agent
  stamp. Previously the matchers built a bare `&http.Client{Timeout: 30s}`
  that bypassed the project's transport configuration, so SWH /
  ClearlyDefined lookups failed on TLS-intercepting corporate
  proxies even when registry pulls worked. (post-stage-13 review F-009)
- `--offline-db` load failures now surface as `ExitInvalidArgs`
  instead of silently disabling the local matcher / CPE chain.
  Air-gapped CI was previously vulnerable to a typo in the path
  shipping a green build with empty enrichment. Both the
  fingerprint matcher chain and the CPE chain now propagate the
  error through to `enrich`'s exit code.
  (post-stage-13 review F-011)
- Local CPE dictionary loader now emits a `WARN cpe.local.skip`
  log per file that fails to read, parse, or decode, and a final
  `INFO cpe.local.loaded entries=N skipped=M` summary. Per-file
  failures still don't abort the load (intentional — one typo in
  a 10 000-entry catalogue should not lose the other 9 999), but
  they are no longer invisible. (post-stage-13 review F-010)
- SPDX JSON loader no longer panics on inputs where the upstream
  parser yields a nil entry inside the `packages` slice (e.g. some
  malformed documents the fuzzer found). The mapper now skips nil
  package entries instead of dereferencing. Discovered by
  `FuzzReadJSON/76ba352485d14925` corpus entry, now part of the
  regression suite.
- SBOM input is now capped at 256 MiB across every reader (format
  detector, CycloneDX, SPDX JSON / tag-value, CLI stdin and file
  paths). Previously every loader called `io.ReadAll` with no upper
  bound; a runaway scan or hostile input could OOM the process
  before parsing started. Inputs above the cap are rejected with
  `ErrSBOMTooLarge`. (post-stage-13 review F-005)
- The `enrich` output writer's `Close()` error is now checked. A
  flush failure on output (disk full, broken pipe, FS quota) used
  to silently produce a truncated SBOM with exit code 0; it now
  surfaces as `ExitOutputWrite`. (post-stage-13 review F-003)
- SBOM format detection now strips a leading UTF-8 BOM
  (`0xEF 0xBB 0xBF`) before the shape check. Previously, SBOMs saved
  by Windows tooling (Notepad, PowerShell, some Excel exports)
  returned `unrecognised format` because the BOM is not Unicode
  whitespace. UTF-16 inputs (`0xFF 0xFE` / `0xFE 0xFF`) now produce
  a clear `ErrUTF16NotSupported` error instead of silent
  `FormatUnknown`. (post-stage-13 review F-002)
- Auto-detection now correctly resolves locally-built images via the
  Docker / Podman daemon before attempting a registry pull. Previously
  failed with `401 UNAUTHORIZED` when the image existed only in the
  local daemon. Probe is gated by a 2-second timeout and a cheap
  socket-existence check, so the new behaviour adds at most a few
  microseconds when no daemon is running. (ADR-0017)
- Format detection now survives truncation of the 64 KiB peek window:
  large minified CycloneDX SBOMs (Syft 1.34+, ~MiB-scale single-line
  JSON) are classified correctly instead of returning
  `unrecognised format`. (ADR-0016)
