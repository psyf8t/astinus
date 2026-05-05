# Changelog

All notable post-stage fixes that change observable behaviour. Stage
deliverables themselves are tracked in the implementation log; this
file is for cross-stage fixes that an operator might bisect against.

## Unreleased — Sprint 3 (Real-World Enrichment)

### Added

- **Sprint 3 acceptance suite — in-process corporate scenarios**
  (S3 Task 7). New `test/acceptance/sprint3/` tree exercising the
  Sprint 3 features end-to-end without docker / syft / real
  cosign. Run with
  `go test -tags acceptance ./test/acceptance/sprint3/...` —
  ~22 seconds on M-class arm64.

  Coverage matrix:

  - `enrichment/` (7 tests) — registry mirror writes Description /
    Licenses / `astinus:registry:source`; lifecycle stamps
    `astinus:lifecycle:status=eol` from the bundled snapshot for
    Python 3.8 / Debian 10; `--no-network` and `--no-registry` /
    `--no-lifecycle` flags fully suppress the corresponding
    enrichers' outbound calls.
  - `corporate/` (8 tests, 1 expected skip) — mirror `replace`
    forbids fallback to the public registry even on 404; mirror
    `fallback` traverses primary→secondary; mTLS handshake
    succeeds with the configured client cert and silently skips
    enrichment when the cert is missing; `--no-network` air-gapped
    runs still complete with the bundled lifecycle snapshot;
    bearer-token-from-env auth round-trips through the
    `token_env` config.
  - `signing/` (2 tests, 1 conditional skip) — missing cosign
    binary surfaces `ExitSigning(50)` with a recovery hint; full
    sign+verify roundtrip when `cosign` is on PATH (skipped
    otherwise).
  - `gate/` (2 tests) — `--fail-on=high` exits with the expected
    code set on a no-license / no-CPE component;
    `--fail-on=critical` against a fully-declared runtime SBOM
    exits 0.

  In-process fakes shipped in `test/acceptance/sprint3/helpers/`:
  `FakeNpmMirror`, `FakeProxy`, `SpyServer`, `MTLSBundle`,
  `MinimalOCIImage`, `WriteMirrorsConfig`. Astinus binary built
  once per `go test` invocation and shared across every subtest.

  Performance baseline: `test/benchmarks/sprint3_perf_test.go`
  (build tag `benchmark`) — `BenchmarkRegistryEnrichment_LocalMirror`
  + `BenchmarkLifecycleEnricher_BundledOnly`. ADR-0037.

- **SBOM signing via Cosign** (S3 Task 6 — SLSA L2+ enabler).
  New `internal/sign/` post-render stage that wraps the `cosign`
  binary as a subprocess. Two modes: `cosign-key` (key-based) and
  `cosign-keyless` (OIDC, with the token Cosign auto-detects from
  CI env). Two output destinations: `--attach-to-image <ref>`
  attaches an in-toto attestation to an OCI image; or
  `--signature-output <path>` writes a detached signature blob.

  Corporate Sigstore endpoints (private Rekor / Fulcio / TUF
  mirror) flow through the env vars Cosign already understands —
  CLI flags `--rekor-url` / `--fulcio-url` / `--tuf-mirror`
  translate to `COSIGN_REKOR_URL` / `COSIGN_FULCIO_URL` /
  `TUF_ROOT`. The existing `--ca-cert` flag (Stage 10) reaches
  Cosign via `SSL_CERT_FILE`.

  Sensitive args (key paths, tokens, certs) are redacted in the
  `sign.cosign.start` log line so a verbose-debug session doesn't
  leak operator material.

  Subprocess approach (not `sigstore-go` library) chosen
  deliberately — bundling sigstore-go would have grown the
  Astinus binary from ~12 MiB to ~60 MiB. Operators install
  Cosign separately (it's already on every CI runner). The wrapper
  surfaces a clear `ErrTooling` ("install cosign") when the
  binary isn't on PATH. ADR-0036.

  CLI flags:
  - `--sign-with cosign-key | cosign-keyless` (empty = signing off)
  - `--signing-key <path>` — Cosign private key file.
  - `--signing-key-password-env <var>` — env var holding the key
    password (default `COSIGN_PASSWORD`).
  - `--attach-to-image <ref>` OR `--signature-output <path>`
    (mutually exclusive; one required).
  - `--rekor-url`, `--fulcio-url`, `--tuf-mirror`,
    `--cosign-path`.

  New top-level subcommand `astinus verify` wraps
  `cosign verify-blob` (detached signature + key) and
  `cosign verify-attestation` (image-attached + OIDC identity
  constraint). Same corporate-Sigstore flag set as the sign side
  for round-trip verification.

  New exit code `ExitSigning = 50` — non-fatal, the SBOM file
  stays on disk so the operator can re-sign manually after
  fixing the Cosign config.

- **Lifecycle / EOL data enrichment** (S3 Task 5). New
  `internal/enrich/lifecycle/` pipeline stage that maps OS /
  runtime Components (Node, Python, Go, Java, Debian, Ubuntu,
  Alpine, Postgres, MySQL, Redis, Kubernetes, Docker, …) to
  endoflife.date products and stamps `astinus:lifecycle:*`
  properties: product, cycle, release-date, active-support-end,
  EOL, LTS, latest-release, status (active / maintenance / eol /
  unknown), days-until-eol, source, fetched-at.

  Two-tier Source chain (`--lifecycle-mode`): online-only,
  offline-only (bundled embedded snapshot), or hybrid (default —
  online first, bundled fallback). Embedded seed snapshot covers
  ~12 popular products (3 KiB JSON); operators refresh richer
  copies via `astinus lifecycle update --output <path>` and
  point the enricher at the file via `--lifecycle-snapshot`.

  Reuses the S3-Task-4 mirror plumbing (auth / mTLS / proxy /
  per-mirror TLS) — entries with `ecosystem: lifecycle` in
  `--mirrors-config` route to internal Artifactory / Nexus /
  whatever-mirror operators run for endoflife.date in air-gapped
  environments.

  Operator-visible `WARN lifecycle.eol` log fires when an EOL
  Component is matched (`status=eol`) so security teams see
  unsupported software at scan time without parsing the SBOM.

  ADR-0035.

  CLI:
  - `--no-lifecycle` — disable the entire stage.
  - `--lifecycle-mode online | offline | hybrid` (default hybrid).
  - `--lifecycle-snapshot <path>` — operator snapshot file
    (overrides embedded).
  - `astinus lifecycle update --output <path>` subcommand to
    refresh the snapshot from endoflife.date (or a configured
    mirror).

- **Package-registry metadata enrichment** (S3 Task 4 — flagship
  Sprint 3 feature). New pipeline stage
  `internal/enrich/registry/` that fetches license / supplier /
  homepage / repository / hashes / description / bug-tracker /
  documentation from per-ecosystem package registries and projects
  them onto each Component (fill-only — never overrides upstream
  values). Per-ecosystem Source registry; PURL-routed dispatch;
  layered cache (memory + on-disk JSON, sharded SHA path); negative-
  result caching so re-runs on the same SBOM are free.

  Implemented sources (full): npm, PyPI, Maven, golang.
  Stub-registered sources (return ErrNotFound; full implementation
  documented as ADR-0033 §6 follow-up): cargo, gem, nuget, deb, apk,
  repology, ecosyste-ms.

  Provenance: `astinus:registry:source` / `astinus:registry:fetched-at`
  on every enriched Component, plus `astinus:registry:homepage` /
  `:repository` / `:bug-tracker` / `:documentation` properties when
  the registry yields URLs (the canonical model doesn't carry
  CycloneDX externalReferences as typed fields — projection via
  properties keeps round-trip clean).

  ADR-0033 (architecture).

- **Corporate mirror / auth / mTLS / proxy support** (S3 Task 4
  companion). Every package-registry fetch flows through a
  per-ecosystem mirror chain (`mode: replace` for air-gapped
  default; `mode: fallback` for hybrid). Auth flavours: bearer,
  basic, custom header (with the JFrog `X-JFrog-Art-Api` pattern
  fully supported). Per-mirror TLS overrides include a corporate
  CA bundle and mTLS client cert/key. Secrets read from env vars
  at request time so the YAML never carries them. Proxy support
  inherited from `http.DefaultTransport.Clone()` (honours
  `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`). `--no-network` and
  `--no-registry` provide complete opt-out paths.

  ADR-0034.

  CLI flags:
  - `--no-registry` (default off) — disable the entire stage.
  - `--mirrors-config <path>` — YAML with per-ecosystem mirror
    + auth + TLS entries.
  - `--registry-cache-dir <path>` — enable on-disk cache (default
    memory-only).
  - `--registry-cache-ttl <duration>` — cache entry TTL (default
    7 days).

  YAML schema: `internal/config/mirrors.go` (top-level `mirrors:`
  key — distinct from the existing `registries:` key which targets
  image-pull auth).

- **Syft baseline noise prefilter** (S3 Task 3). New
  `internal/enrich/syftprefilter/` enricher that runs FIRST in the
  pipeline (Dependencies = nil) and applies the bundled
  `pathclassifier` rules to Syft-supplied `type=file` Components,
  dropping noise paths (`/etc/cron.d/...`, `/etc/apt/...`,
  `/etc/pam.d/...`) and pruning orphaned edges from
  `sbom.Relationships`. Reuses the same classifier the untracked
  enricher uses (PRSD-Task-1 + operator overrides via
  `--rules-file`), so a "skip" verdict for an untracked walk is
  also a "skip" verdict for a Syft baseline row. Forensic
  operators can disable the entire stage via
  `--no-syft-prefilter`. Per the task acceptance metric, expected
  reductions on the v0.2 reference image: total components 5800 →
  ~2200-2500; type=file count 3992 → ~500; SBOM file size ~5MB →
  ~1.5MB. ADR-0032.

  CLI flag: `--no-syft-prefilter` (default off; filter on).

### Changed

- **Compliance severity policy per ecosystem** (S3 Task 2). The
  Sprint 2 benchmark output had 11949 findings on 5800 components
  — 200% — dominated by NTIA-SUPPLIER stamped at blanket
  SeverityMedium for ecosystems where "supplier" is structurally
  meaningless (npm packages, files, distro packages with derivable
  supplier). Compliance teams reported they ignored the output
  because the actionable-vs-noise ratio was too low.

  Fix: a new per-ecosystem severity policy
  (`internal/policy/builtin/compliance/severity_policy.go`)
  classifies findings by RuleID + ComponentType + PURL ecosystem.
  The compliance enricher applies the policy AFTER all validators
  have emitted findings; SeverityIgnored findings (e.g. any rule on
  a `type=file` Component) are dropped entirely from output and
  counters. Operators can override the bundled defaults via
  `--compliance-config <yaml>`. ADR-0031.

  Output schema additions:
  - `astinus:compliance:actionable-findings-count` — sum of
    critical + high + medium (the set security teams should triage
    first).
  - `astinus:compliance:info-count` — informational findings (e.g.
    npm NTIA-SUPPLIER) for transparency without noise.
  - New `ignored` severity value: SeverityIgnored sorts below
    SeverityInfo, never appears in output, never trips
    `--fail-on`.

  Behavior change for downstream consumers: the per-Component
  `astinus:compliance:finding:NTIA-SUPPLIER` value is now
  ecosystem-dependent (info / low / medium / high) instead of
  always "medium". The `--fail-on` gate consumes post-policy
  severities, so a `--fail-on medium` gate no longer trips on every
  npm package missing a supplier field.

### Added

- `--compliance-config <path>` CLI flag — loads a YAML file with
  `compliance.severity_overrides` entries that beat the bundled
  per-ecosystem defaults. ADR-0031.

### Fixed

- **SubComponents extraction for binary components** (S3 Task 1).
  The Sprint 2 benchmark output had no `subcomponents` and no
  dependency edges for static Go binaries (yq, dive, etc.) even
  though the multi-modal extractor registry was capable of
  producing them — the extractor was wired only into the
  untracked enricher's per-file walk, so binaries already
  populated by the upstream SBOM (Syft tags `/usr/local/bin/yq`
  with the file path in Evidence.Locations) silently skipped the
  registry. The flagship "single binary scan recovers full module
  graph" feature was effectively dead in production output.

  Fix: a new `internal/enrich/extractor/` enricher runs after
  `untracked` and projects extracted dependencies as top-level
  `model.Component` entries (PURL-deduped across parents) plus
  `RelationshipDependsOn` edges in `sbom.Relationships`. The
  CycloneDX writer already serialises those edges as the canonical
  `dependencies[].dependsOn` graph, so vulnerability scanners see
  the embedded modules as first-class components.

  Pipeline order: `attribution + basediff → untracked → extractor
  → cpe → dedup → compliance` (encoded via `Dependencies()`
  declarations + topological sort, regression-tested in
  `extractor/order_test.go`). ADR-0030.

### Added

- **`internal/enrich/extractor` enricher** (S3 Task 1) — auto-
  registered in production CLI; no operator-facing flag (the
  feature is on by default and can only be disabled via
  `--disable extractor`).

### Fixed

- **CPE confidence handling and false-positive rejection** (S3 Task 0).
  The Sprint 2 benchmark output for `yq` carried three `astinus:cpe:N`
  properties — a Linksys router CPE, a German auction-site CPE, and
  the legitimate `yq:v4` entry — all stamped with a single blanket
  `astinus:cpe:confidence=high`. Vulnerability scanners reading the
  enriched SBOM raised CVEs against unrelated hardware, breaking the
  security workflow. Fix: per-Candidate confidence scoring,
  Threshold-based classification (primary / alternative / rejected),
  hard rejection of hardware-type CPEs (`type=h`) on software PURLs,
  per-attribute MatchDetails, and a new output schema:
  - primary CPE → CycloneDX `cpe` field
  - alternatives ≥ 0.50 → `astinus:cpe:alternative:N` properties
  - rejected → DEBUG log only (or `astinus:cpe:rejected:N` with
    `--include-rejected-cpe`)

  Confidence stamps changed from string labels (`"high"` / `"low"`)
  to numeric format (`"0.95"` / `"0.50"`); SARIF and summary
  renderers parse both for backward compatibility. The deprecated
  `astinus:cpe:N` numbered property is no longer emitted by
  Astinus (still understood on read for v0.2 SBOM round-trip).
  ADR-0029.

### Added

- `--include-rejected-cpe` CLI flag emits `astinus:cpe:rejected:N`
  properties for diagnostic inspection. Default off; rejected
  candidates always appear in the DEBUG `cpe.rejected` log.

## v0.2.0 — 2026-05-03 (Production Readiness Sprint)

The Production Readiness Sprint (PRSD-Task-0..9) closes Track A
(industry compliance), Track B (vulnerability-scanning quality)
and Track C (forensic-grade attribution) and lands the unified
observability layer the spec called for. v0.2.0 is the first
release suitable for production CI pipelines.

### Added — net-new functionality

- **Multi-runtime image normalization** (PRSD-Task-0): runtime
  detection across Docker / BuildKit / Podman / Buildah / Kaniko;
  attribution-confidence stamping; provenance round-trip. ADR-0018.
- **Declarative path classifier** (PRSD-Task-1): YAML-driven rule
  bundles, `--rules-file` flag, character-trie dispatch. ADR-0019.
- **Content-addressable basediff** (PRSD-Task-2): SHA-256 across
  paired images, multi-stage `COPY --from` survives squash, in-tree
  Bloom filter. ADR-0020.
- **Filesystem-aware clustering** (PRSD-Task-3): 9-anchor +
  density-scoring untracked pre-pass. `--no-cluster` flag,
  `astinus:cluster:*` properties. ADR-0021.
- **Multi-modal binary extractor** (PRSD-Task-4): Go buildinfo +
  Rust `.dep-v0` + Java 3-tier + Python METADATA + ELF + PE
  registry. ADR-0022.
- **CPE online/offline/hybrid modes** (PRSD-Task-5): pluggable
  Source registry; in-tree token-bucket rate limiter; NVD API +
  ClearlyDefined sources; `--cpe-mode` and `--nvd-api-key` flags.
  ADR-0023.
- **Topological pipeline ordering** (PRSD-Task-6): `Enricher.Dependencies()`
  + in-tree TopoSort (Kahn's, stable input-order tie-break);
  `pipeline.order` log line. ADR-0024.
- **Compliance validation framework** (PRSD-Task-7): NTIA, EU CRA,
  CycloneDX-structural, SPDX-structural validators; `--fail-on`
  gate; per-finding SBOM properties. ADR-0025.
- **Unified observability and telemetry** (PRSD-Task-8): event
  vocabulary constants; in-tree Prometheus registry +
  `--metrics-output stdout|stderr|file:/path`; tracing stub
  (OTel deferred); `--tracing-endpoint` flag; static "no stdlib
  log" enforcement. ADR-0026.
- **Acceptance test suite** (PRSD-Task-9): 8 image-type tests +
  3 external validators + 3 vuln scanners + 5-runtime matrix +
  perf benchmarks; `acceptance.yml` nightly CI workflow.
  ADR-0027.

### Changed

- Production CLI now exposes `--rules-file`, `--no-cluster`,
  `--cpe-mode`, `--nvd-api-key`, `--fail-on`, `--metrics-output`,
  `--tracing-endpoint` (additive — every existing flag still
  works the same way).
- Pipeline `Run` migrated to `telemetry.Event*` constants for
  every emitted log; opt-in `WithMetrics` / `WithTracer`
  builders attach observability per-run.

### Notes

- No new third-party dependencies were added across the entire
  sprint (PRSD-Task-1..9). Bounded algorithms (trie, bloom,
  TOML, extractors, token-bucket, topo-sort, structural
  validators, Prometheus exposition, tracing stub) are in-tree;
  same precedent that kept the binary at ~12 MiB despite ten
  new internal packages.

## Unreleased

### Performance

- Untracked enricher now restricts the matcher chain (SWH /
  ClearlyDefined / local) to high-value file categories
  (Executable + Library) by default. Unknown / Script / Archive
  files almost never match content-hash catalogues and previously
  dominated wall-clock against rate-limited public APIs. New
  `Options.MatcherInclude{Unknown,Scripts,Archives}` flags opt
  back in for debug. Files smaller than
  `Options.MatcherMinFileBytes` (default 4 KiB) are also skipped
  — too small to be vendored binaries.
  (post-Stage-13 hardening Task 4.1)
- Untracked enricher's matcher.Lookup calls now run in a bounded
  worker pool (`Options.MatcherWorkers`, default 16) AFTER the
  layer walk completes, instead of being inlined synchronously
  per file. The rate limiter still gates token acquisition; the
  parallelism gain is in overlapping HTTP round-trip latency
  (each SWH lookup is ~1–2 s of network time). Combined with the
  category filter, this brings the with-network full-pipeline
  wall-clock from **47 minutes (baseline) → 4 minutes 36
  seconds** on the reference ~533 MiB Debian/Node.js image, well
  under the 5-minute target. New per-Lookup `MatcherTimeout`
  (default 5 s) caps a single slow SWH response.
  (post-Stage-13 hardening Task 4.2)
- Bumped matcher rate-limit defaults from 5/s burst 10 to 20/s
  burst 30. The category filter caps total lookups at a few
  hundred per scan, so even 20 req/s never sustains long enough
  to risk a Software Heritage rate-limit ban.
  (post-Stage-13 hardening Task 4.3)
- Untracked stats log now includes `matcher_hits` so operators
  can see how many lookups produced a real hit.

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
