# Changelog

All notable changes that affect operator-visible behaviour or the
public CLI / output surface.

> **About ADR references.** Architecture Decision Records are kept
> internal in v0.0.x — references like `ADR-0036` in the entries
> below correspond to in-tree documents that are not yet published.
> The public ADR layout is being decided in
> [#9](https://github.com/psyf8t/astinus/issues/9).

## Unreleased

### Fixed

- **`--base auto` now resolves base for `debian:trixie-slim` /
  `debian:13-slim` (Debian 13) images.** Run #4 measured
  D-postgres origin coverage at **0 %** (4134/4134 components
  marked `unknown`) because `postgres:17` is built on
  `debian:trixie-slim` (Debian 13) and the bundled known_bases.json
  captured `2026-05-13` had no debian:13 entry — trixie went GA in
  late 2025, after the original Sprint 4 Task 6 catalogue was
  assembled. Refreshed the snapshot
  (`captured_at = 2026-05-14`, `next_update_due = 2026-08-14`) with
  seven new entries: `debian:13-slim`, `debian:trixie-slim`,
  `python:3.12-slim-bookworm`, `python:3.13-slim-bookworm`,
  `python:3.13-slim-trixie`, and `alpine:3.23.4`. The Python:slim
  entries are forward-prep for Sprint 6 Task 4 (layered intermediate
  bases on B-airflow). See ADR-0060.

- **Preserve all multi-CPE candidates from Syft input.** Run #4
  measured one strict Grype TP regression on C-nginx:
  CVE-2025-60876 on `ssl_client@1.37.0-r30` (Medium) — the package
  was intact in both SBOMs but Astinus's CPE consolidation
  dropped the alt-CPE candidates Grype was matching on. Syft emits
  multiple `syft:cpe23` properties per multi-product package
  (busybox ssl_client → 5 vendor/product variants); CycloneDX
  permits duplicate property names but Astinus's CDX reader
  collapsed them through `map[string]string` and kept only the
  last. Two coordinated ingest-side fixes plus a defensive cap:
  - New `appendSyftCPEs` runs at `componentFromCDX` time, walks
    the raw CDX Property slice (preserves duplicates), and
    appends every `syft:cpe23` value to `c.CPEs` before
    `propsFromCDX` collapses.
  - `hydrateAstinusFields` now uses `isNumericExtraCPEKey` to
    accept only the `astinus:cpe:<N>` numeric shape — the
    pre-S6 overbroad `strings.HasPrefix("astinus:cpe:")` sweep
    swept metadata properties (`:source`, `:confidence`,
    `:scope`, `:alternative:1:source`, etc.) into `c.CPEs`
    where the classifier rejected them as malformed CPEs. Noisy
    + amplified the alt-CPE confusion. Now those properties
    stay in `c.Properties` where they belong.
  - `writeResults` caps emitted alternatives at
    `maxAlternativesEmitted = 10`; `astinus:cpe:alternatives-count`
    records the pre-cap classifier count so operators see when
    truncation fired.
  See ADR-0062.

- **`astinus:origin` on Alpine images now classifies apk packages by
  earliest-introducing layer, not by presence in
  `/lib/apk/db/installed`.** Run #4 measured C-nginx origin accuracy
  at **15 %** (3/20) — every apk package the nginx Dockerfile added
  on top of the alpine base was misclassified as `base-image`. Root
  cause was twofold: (1) no apk-earliest-layer infrastructure — the
  FileMap's last-touch lookup against any apk-managed path collapsed
  every apk row to the LAST layer that ran `apk add` / `apk del`,
  and (2) basediff's content strategy ran `pathInBase` on
  `/lib/apk/db/installed` which lives in both the alpine base AND
  every apk-touching layer, so every apk row hit
  `OriginBaseImage`. Sprint 4 Task 2 (ADR-0041) listed an
  apk-earliest path as an open question; the DoD checkbox was
  ticked but the production code was never written. S6 Task 2 fills
  both gaps. The layer walker now parses `/lib/apk/db/installed`
  during the existing tar stream and builds a `(name@version) →
  earliest layer index` map; new
  `FileMap.ApkEarliestLayer(name, version)` returns the layer
  descriptor. Attribution enricher gains `applyApkEarliest` that
  runs after the default stamper, looks up apk components
  (`pkg:apk/...` PURL) in the index, and OVERRIDES `LayerInfo` +
  stamps `astinus:layer:source = "apk-earliest-layer"`. basediff's
  `pathsForComponent` filters `/lib/apk/db/installed` out for apk
  components so the content strategy doesn't double-count the DB
  path. Non-Alpine images and non-apk components are unaffected.
  See ADR-0059.

- **CPE 2.3 attribute values now backslash-escape special characters
  per NIST IR 7695 §6.1.2.5.** Previous build emitted literal `:` and
  `+` inside the version slot, which made round-trip `Parse(Build(...))`
  silently reject the URI (`cpe23Regex`'s `[^:]*` slot pattern saw the
  embedded `:` as a slot boundary), and intermediate tooling layers
  URL-encoded the unescaped output as `%3A` / `%2B` — also
  non-conformant. Affected every deb package with epoch versions
  (`libcap2 1:2.75-10+b8`, `libaudit-common 1:4.0.2-2`, …) plus any
  `+` / `@` / `?` / `/` etc. in the slot. Run #4 measured 27 affected
  CPEs on D-postgres and ≥ 2 on B-airflow; not visible on Alpine
  images (apk versions don't carry the spec special chars). New
  `EscapeCPE23Attribute` / `UnescapeCPE23Attribute` + escape-aware
  `splitCPEv23` cover all 27 spec characters; `cpe.Build` +
  `CPEv23.String` now route every attribute through them. `Parse`
  unescapes attribute values so callers see the human-readable form.
  `applyVersionNormalization` + `cpeVendor` switched to the
  escape-aware splitter so the S5-T3 v-prefix strip + S4-T3 vendor
  reject still work on deb-epoch CPEs. Syft-inherit path unchanged
  (Syft is already spec-correct). See ADR-0058.

- **CPE enricher now bounded by per-call (10 s), per-source (60 s),
  and total-phase (3 m) wall-time timeouts.** Previous builds could
  hang indefinitely on established but idle TCP connections to
  online CPE sources — run #4 reproducer on `apache/airflow:slim-
  latest` (≈2400 components) sat at 0% CPU for over 6 minutes mid-
  enrich and was killed after 19 minutes. Root cause was a
  combination of the `cpe.Resolver` interface dropping the
  enricher's `context.Context` (the orchestrator fabricated
  `context.Background()` internally, so cancellation never reached
  the rate limiter) and anonymous NVD's 5-req/30-s token bucket
  amplifying any single hung call into a multi-hour Wait. Fix
  layers three bounds:
  - **Per-call HTTP deadline** via `context.WithTimeout` in
    `MultiSourceResolver.callSource` — applies to every Source's
    `Match` invocation regardless of `http.Client.Timeout`.
  - **Per-source `SourceBudget`** caps cumulative time any single
    online source can consume across a run; once exhausted the
    source is silently skipped for the remaining components.
  - **Total enricher cap** wraps `Enricher.Enrich(ctx, ...)` with
    `context.WithTimeout(ctx, totalCap)`; the walk exits cleanly
    on cap-fire and stamps SBOM metadata.
  Three new CLI flags expose the bounds:
  `--cpe-total-timeout` (3 m default), `--cpe-source-timeout`
  (60 s), `--cpe-call-timeout` (10 s). New opt-in interface
  `cpe.ContextResolver` propagates ctx end-to-end while preserving
  the legacy `Resolver` contract for the bundled/heuristic chain.
  Mode-specific behaviour preserves the ADR-0051 contract: in
  `--cpe-mode auto` a timeout WARNs + emits partial results +
  exits 0; in `--cpe-mode hybrid` it surfaces
  `cpe.ErrSourceUnavailable`, which the CLI maps to exit 60
  (`ExitCPESourceUnavailable`) with an actionable resolution
  message. New SBOM metadata stamps:
  `astinus:cpe:total-cap-hit`, `astinus:cpe:elapsed-seconds`,
  `astinus:cpe:components-processed`, and the per-source
  `astinus:cpe:source-status:<name>` family carrying
  `complete` / `budget-exhausted:<dur>` / `timeout` / `errored`.
  Operators driving large SBOMs now see periodic
  `cpe.enricher.progress` logs every 100 components or 10 s.
  See ADR-0057.

### Added

- **Sprint 6 acceptance suite (`test/acceptance/sprint6/`).**
  Eleven in-process tests across `quality/` (T0 wall-time
  metadata stamp; T1 deb-epoch CPE backslash-escape vs
  URL-percent; T2 apk-earliest layer override; T3 trixie
  known-bases entry + actionable FallbackReason; T4 python:slim
  layered chain stamps; T5 multi-`syft:cpe23` alt-CPE
  preservation) and `features/` (T6 VEX flag round-trip; T7
  policy deny exits 40; T8 license deny exits 40; T8 license
  allow stamps; Stage 14 VEX+policy+license composition). Build
  tag `acceptance`; full suite hermetic + ≈ 20 s wall-clock on
  M-class arm64. Reuses Sprint 3 helpers (binary builder +
  RunEnrichOK) and Sprint 4 helpers (OCIImageWithFiles +
  WriteCDXSBOM + MetadataProperty). 4-image pinned-digest
  bundle (Grafana / Airflow / Nginx / Postgres + ground-truth
  JSON + Grype-binary delta gates + per-image metric pins) +
  CI matrix workflow explicitly deferred to a Sprint 7
  follow-up. See ADR-0066.

### Fixed

- **CPE wall-time bounds now stamp configured values on SBOM
  metadata.** Pre-S8 the only wall-time SBOM metadata was the
  fire-state (`astinus:cpe:total-cap-hit`) + elapsed
  (`astinus:cpe:elapsed-seconds`) — operators reading
  `total-cap-hit=true elapsed=180.05` had to cross-reference
  the CLI invocation to know the cap was 3m. Three new
  metadata stamps land on every CPE-enricher run:
  `astinus:cpe:total-cap-configured`,
  `astinus:cpe:source-timeout-configured`,
  `astinus:cpe:call-timeout-configured`. Values are
  `time.Duration.String()`-formatted (`3m0s`, `60s`, `10s`).
  Zero / unset durations delete the stamp rather than writing
  misleading `0s` — legacy resolvers without timeout tracking
  see no extra metadata, no regression. New
  `MultiSourceResolver.Timeouts()` accessor surfaces the
  configured durations from the resolver; the enricher's
  `resolverTimeouts()` helper type-asserts so non-MultiSource
  chains (BundledResolver / Chain) flow through unchanged.
  See ADR-0057 (amended).

- **License policy verified on `87bff5c` baseline (Sprint 8 Task 5).**
  The Sprint 8 task spec is path-renamed-only vs Sprint 6 / 7
  Task 8. The implementation (internal/license/expr.go SPDX
  allow/deny + applyLicenseGate in CLI + ADR-0065) shipped under
  S6-T8 satisfies the Sprint 8 DoD unchanged. `go test
  ./internal/license/... ./internal/cli/...` GREEN; acceptance
  gates `TestS6T8_LicenseDenyGPLFailsTheGate` +
  `TestS6T8_LicenseAllowOnlyMITPassesAllowedComponent` +
  `TestS6Stage14_VEX_Policy_License_ComposeCleanly` GREEN. No
  code change.

- **Policy framework verified on `87bff5c` baseline (Sprint 8 Task 4).**
  The Sprint 8 task spec is path-renamed-only vs Sprint 6 / 7
  Task 7. The implementation (internal/policy/ rules + loader +
  applyPolicies in CLI + ADR-0064) shipped under S6-T7 satisfies
  the Sprint 8 DoD unchanged. `go test ./internal/policy/...
  ./internal/cli/...` GREEN; acceptance gates
  `TestS6T7_PolicyDenyFailsTheGate` +
  `TestS6Stage14_VEX_Policy_License_ComposeCleanly` GREEN. No
  code change.

- **VEX support verified on `87bff5c` baseline (Sprint 8 Task 3).**
  The Sprint 8 task spec is path-renamed-only vs Sprint 6 / 7
  Task 6. The implementation (internal/vex/ parser + applyVEXSuppression
  in CLI + ADR-0063) shipped under S6-T6 satisfies the Sprint 8
  DoD unchanged. `go test ./internal/vex/... ./internal/cli/...`
  GREEN; acceptance gates `TestS6T6_VEXSuppressesCVEFinding` +
  `TestS6Stage14_VEX_Policy_License_ComposeCleanly` GREEN. No
  code change.

- **CPE alt-candidate preservation verified on `87bff5c` baseline.**
  Sprint 8 README's run-3 benchmark repeated the C-nginx
  `ssl_client` CVE-2025-60876 TP regression observation —
  verification confirms the S6-T5 implementation closing the
  regression (`appendSyftCPEs` preserving multi-`syft:cpe23`
  duplicates, `isNumericExtraCPEKey` narrowing hydration to the
  numeric `astinus:cpe:<N>` shape, `maxAlternativesEmitted = 10`
  cap, S7-T5's `hyper:hyper` cargo correction) is already in
  place on the run-3 baseline and all six unit pins remain
  green. No code change; the run-3 observation reads against a
  pre-S6-T5 code shape rather than what `87bff5c` carries.
  C-nginx end-to-end Grype-binary recovery remains the S8-T6
  acceptance gate. See ADR-0062 (verified).

- **CPE input-normalisation count now stamps on SBOM metadata.**
  S7-T1 added `NormalizeCPEEncoding` to repair URL-percent-encoded
  CPE attribute slots (`%3A` → `\:`, `%2B` → `\+`) at ingest time,
  but the SBOM offered no operator-facing signal that the repair
  fired — run-3 multi-image benchmark on D-postgres normalised
  every Debian-epoch CPE silently. New `astinus:cpe:input-normalised-count`
  property records the per-run count; always present on a
  completed Enrich call so `"0"` (the enricher ran, didn't need
  repairs) is distinguishable from absence (the enricher never
  ran). `NormalizeCPEEncoding` now returns `(string, bool)` —
  the bool surfaces the per-call fire so the enricher's walker
  can accumulate across components. `cpe.complete` slog line
  gains a `cpes_normalised` field so operators triaging from
  logs (not the SBOM) get the same signal. Purely additive — the
  S7-T1 repair logic is byte-for-byte identical; the new property
  joins the existing CPE-mode metadata family. See ADR-0058
  (amended).

- **Sprint 7 close — acceptance suite verified against the
  baseline.** Re-ran `go test -tags acceptance ./test/acceptance/
  sprint4/... ./test/acceptance/sprint5/... ./test/acceptance/
  sprint6/...` GREEN against the post-S7 baseline; 11 in-process
  Sprint 6 gates continue to cover the S6 + S7 amended contracts.
  4-image pinned-digest bundle (Grafana / Airflow / Nginx /
  Postgres + ground-truth JSON + Grype-binary delta gates +
  acceptance-sprint6.yml CI matrix workflow + update_fixtures/
  update.go toolchain) remains deferred to Sprint 8 — same
  trade-off Sprint 6 Task 9 (ADR-0066) made. See ADR-0066
  (amended).

- **Bundled hyper crate CPE mapping corrected.** Sprint 7
  run-2 flagged Astinus's first WORSE CPE-quality verdict
  across all benchmark runs: Syft baseline
  `cpe:2.3:a:hyper:hyper:1.0.0:*:*` (278 NVD matches) vs
  Astinus pre-S7 `cpe:2.3:a:hyperium:hyper:1.0.0:*:*` (0 NVD
  matches). The pre-S7 bundled mapping carried `hyper` →
  `hyperium:hyper` based on the GitHub org name; NVD registers
  the crate under `hyper:hyper` directly. One-line data
  correction in `internal/enrich/cpe/builtin/purl_to_cpe.json`;
  unit test pins the new shape so a future regression fails
  fast. See ADR-0062 (amended).

- **python:slim AddedPackages expanded for broader chain
  coverage.** Sprint 7 run-2 measured B-airflow origin accuracy
  at 70 % (14/20) — +5 % vs run-1, within noise. The Sprint 6
  Task 4 chain visibility stamps work, but the minimal 7-entry
  AddedPackages lists for python:slim entries cover only the
  python interpreter + ca-certificates + libssl3, missing the
  ~14 typical apt-installed runtime deps every python:slim
  image carries (libexpat1, libsqlite3-0, libreadline8,
  libtinfo6, libffi8, libbz2-1.0, liblzma5, libuuid1,
  libcrypt1, libgdbm6, libgdbm-compat4, libncursesw6, tzdata,
  media-types). Expanded all three python:slim entries
  (3.12-bookworm, 3.13-bookworm, 3.13-trixie) from 7 → 21
  packages each. Chain-resolution code path unchanged. See
  ADR-0061 (amended).

- **Debian per-package layer attribution (dpkg-earliest).**
  Sprint 7 run-2 measured D-postgres origin accuracy at 60 %
  (12/20) with **bidirectional** mismatches in the remaining
  40 %: some `debian:trixie-slim` base packages labelled
  `application`, some postgres-Dockerfile-added packages
  labelled `base`. The dpkg status file is rewritten on every
  `apt-get install` / `apt-get remove` / `apt-get upgrade`, so
  the FileMap's last-touch lookup against any deb-managed path
  collapses pre-existing AND newly-added packages onto the
  last apt-touching layer — exactly the apk-earliest problem
  S6-T2 / S7-T2 closed for Alpine. New
  `internal/image/layer/dpkg_db.go` parses
  `/var/lib/dpkg/status` (RFC822-style; ignores continuation
  lines for `Description:` blocks) and builds a
  `(name@version) → earliest layer index` map alongside the
  apk equivalent. New `FileMap.DpkgEarliestLayer(name, version)`
  query. New
  `internal/enrich/attribution/deb_earliest.go::applyDebEarliest`
  runs after applyApkEarliest, overrides LayerInfo for
  `pkg:deb/...` components, stamps `astinus:layer:source =
  deb-earliest-layer`. basediff's `pathsForComponent` filter
  generalises to strip `/var/lib/dpkg/status` for deb
  components; `classifyApkByLayerIndex` fallback generalises
  to deb (LayerIndex == 0 → base, > 0 → application; source
  stamp must match the right ecosystem). See ADR-0060
  (amended).

- **Alpine apk origin classification on empty-paths fallback.**
  Sprint 7 run-2 benchmark measured C-nginx origin accuracy at
  **0 %** (0/20 sampled apk components classified) — regressed
  from the run-1 baseline of 15 % (3/20). Root cause: the
  combination of Sprint 6 Task 2's two pieces produced a
  degenerate case. When Syft stamped ONLY the apk DB path
  (`/lib/apk/db/installed`) on an apk component (the common
  case for apk catalogers that use the DB record as evidence),
  the S6-T2 path-filter stripped it (correct — the DB path is
  metadata, not the artifact) AND the basediff
  `classifyComponent`'s `if len(paths) == 0 { return
  OriginUnknown }` short-circuit returned Unknown, losing the
  layer-index information apk-earliest already resolved. New
  `classifyApkByLayerIndex` fallback fires when the path set
  is empty AND the component carries `astinus:layer:source =
  apk-earliest-layer`: LayerIndex == 0 → OriginBaseImage,
  LayerIndex > 0 → OriginApplication. Restores the dominant
  single-stage alpine-FROM-image pattern (C-nginx). See
  ADR-0059 (amended).

- **Input-side CPE encoding normalisation.** Sprint 7 run-2
  benchmark reported 27 URL-percent violations on D-postgres
  and 2 on B-airflow despite Sprint 6 Task 1's backslash-escape
  fix being in place. Root cause: Astinus's `cpe.Build` +
  `CPEv23.String` correctly emit backslash-escape for
  self-generated CPEs, but `candidatesFromExistingCPEs` read
  inherited CPE strings from input SBOMs verbatim — when an
  upstream tool (Syft/Trivy wrapper, hand-edited fixture)
  emitted `%3A` / `%2B`, the malformed shape rode through to
  the output. New `NormalizeCPEEncoding(cpe string) string`
  helper decodes the recognised URL-percent triplets in each
  attribute slot and re-routes the slot through
  `EscapeCPE23Attribute` to produce the spec-correct backslash
  shape. Runs at ingest time in `candidatesFromExistingCPEs`
  so the rest of the CPE machinery sees the canonical form.
  Recognises the operator-facing common subset (%3A, %2B,
  %40, %5C, %20, %2F, %3F, %3D, %26, %23, %25, %5E, %7E, %3B,
  %2C, plus paren/bracket/brace + the rest of the CPE 2.3
  special set); unknown triplets pass through unchanged so a
  legitimate `%99` in a slot isn't mangled. See ADR-0058
  (amended).

- **CPE-source HTTP transport gains `ResponseHeaderTimeout`
  defense-in-depth.** Sprint 7 run-2 benchmark reported the
  Airflow `--cpe-mode auto` hang as unchanged despite Sprint 6
  Task 0's per-call ctx + per-source budget + total-cap. Root
  cause: the operator transport's `ResponseHeaderTimeout` is
  unset (Go default), so a TCP connection that establishes
  but never sends response headers relied solely on context
  propagation through the `RoundTripper` chain to bound the
  wait. New `buildCPESourceHTTPClient(tr, callTimeout)` helper
  clones the operator transport when it exposes a
  `*http.Transport`, sets `ResponseHeaderTimeout =
  --cpe-call-timeout` on the clone, and caps `Client.Timeout`
  at `2 × callTimeout` (max 60 s). Transport-level timeout
  fires independently of ctx propagation so a pathological
  wrapper that swallows `ctx.Done` can't keep an HTTP request
  alive past the operator-supplied per-call deadline. Fallback
  path for non-`*http.Transport` round-trippers preserves the
  pre-S7 30 s `Client.Timeout`. See ADR-0057 (amended).

- **Compliance gate metadata stamps now reach the rendered SBOM
  file.** Pre-S6-T9 `evaluateComplianceGate` ran AFTER the SBOM
  was rendered to disk in `runPostRenderHooks`, so every VEX /
  policy / license metadata stamp (`astinus:vex:suppressed:*`,
  `astinus:policy:hit:*`, `astinus:license:*`) mutated the
  in-memory SBOM but never landed on the output file.
  Operator-facing contract regression that escaped because the
  unit tests called the apply helpers directly on in-memory
  SBOMs — the binary-level acceptance gates in Sprint 6 Task 9
  caught it. Fix splits the gate into
  `decorateComplianceMetadata` (pre-render, mutates SBOM
  metadata + extends findings) and
  `enforceComplianceThreshold` (post-render, computes the
  `--fail-on` decision over the cached findings). New
  `complianceGateInputs` carries state across the render
  boundary. See ADR-0066.

### Added

- **License policy — SPDX-based allow/deny gate.** Three new
  flags drive the gate without YAML authoring: `--license-allow
  <SPDX-ID>` (repeatable), `--license-deny <SPDX-ID>`
  (repeatable, higher precedence than allow), and
  `--license-require-known` (rejects empty / unparseable
  license declarations). Empty allow+deny + require-known=false
  ⇒ gate disabled. Deny takes precedence over allow: a
  `MIT OR GPL-3.0-only` row fails when GPL-3.0-only is in deny,
  even if MIT is in allow ("if it CAN be released as GPL, treat
  it as GPL"). Components failing the gate become synthetic
  `LICENSE-VIOLATION-<sanitized-purl>` findings at severity
  High; SBOM metadata stamps `astinus:license:gate-mode`,
  `:total-evaluated`, `:total-denied`, `:total-unknown` (always)
  + per-violation `astinus:license:denied:<purl>` and
  `astinus:license:unknown:<purl>` (per row). New
  `internal/license/` package with `EvaluateComponent` and a
  minimal SPDX expression parser (`extractSPDXIDs` handles
  OR/AND/WITH + parentheses; covers every license expression in
  the observed SBOM park; no new dependency). Composes with
  Sprint 6 Task 6 VEX (per-vuln) and Task 7 policy framework
  (per-rule) — Stage 14 trifecta complete. See ADR-0065.

### Added

- **Operator-supplied YAML policy framework.** New `--policy
  <file>` CLI flag (repeatable; policies stack in invocation
  order). YAML rules carry component matchers (`purl_matches`
  glob, `ecosystem`, `version_below`, `has_property`) and
  finding matchers (`id_prefix`, `severity`) with arbitrary
  `all`/`any`/`not` composition. Three action types:
  - `deny` adds a synthetic `POLICY-<rule-id>` finding to the
    compliance gate (severity High) — useful for blocking
    components regardless of CVE catalog status (e.g.
    "log4j-core < 2.17.0 is forbidden").
  - `allow` suppresses matching CVE-shaped findings —
    operator-vouched-safe (e.g. "Critical CVEs on
    `astinus:origin = base` are vendor responsibility").
  - `warn` stamps SBOM metadata only (no gate effect).
  Strict YAML decoder (unknown keys → error). SBOM stamps
  `astinus:policy:hit:<rule-id> = <action>:<message>` per
  decision + aggregate `astinus:policy:total-hits`. Composes
  with `--vex` (S6-T6 ADR-0063): gate evaluates VEX first,
  then policy, then `--fail-on` threshold. `remap_severity`
  action and Rego support deferred to Sprint 7+. See ADR-0064.

### Added

- **VEX (Vulnerability Exploitability eXchange) support.** New
  `--vex <file>` CLI flag (repeatable) accepts OpenVEX 0.2 and
  CycloneDX 1.5 VEX documents (format detected by content). The
  compliance gate suppresses CVE-shaped findings whose
  `(vulnID, componentPURL)` matches a `not_affected` or `fixed`
  statement in the loaded VEX store. SBOM metadata stamps
  `astinus:vex:suppressed:<CVE> = <status>:<justification>` per
  suppression, `astinus:vex:total-suppressed` (count), and
  `astinus:vex:sources` (comma-joined file paths) make the
  decisions auditable from the SBOM alone. PURL matching
  supports exact equality + `@*` wildcard on either side;
  version-range matching is deferred to a future task. Every
  suppression emits a `compliance.vex.suppressed` WARN log
  carrying cve / component / purl / status / justification /
  source. Non-CVE compliance findings (NTIA / EU-CRA) flow
  through unchanged. New `internal/vex/` package exposes
  `Store`, `Effect`, `LoadStore`, `DetectFormat` for future
  extensions. See ADR-0063.

- **Layered base-image chain resolution.** Run #4 measured
  B-airflow origin accuracy at 65 % (13/20): the 7 mismatches were
  deb packages installed by the airflow Dockerfile on top of
  `python:3.13-slim-bookworm` (libpq5, libsasl2-2, FreeType libs)
  that Astinus's single-level base detection swept into the
  `base-image` bucket. `python:3.13-slim-bookworm` is itself layered
  on `debian:bookworm-slim`; treating "anything in detected base" as
  one bucket loses the nuance between python-slim-introduced
  packages and parent-debian-inherited packages. New
  `KnownBaseEntry.ParentBase` + `AddedPackages` JSON fields (both
  `omitempty` — backwards-compat). New `BaseChain` type +
  `AutoDetector.DetectChain` walks the `parent_base` link up to 5
  levels (cycle-safe). The basediff enricher stamps
  `astinus:basediff:chain-depth` + `astinus:basediff:chain:<N>` on
  SBOM metadata (0 = most-specific). Components classified
  `OriginBaseImage` whose name appears in a chain level's
  `AddedPackages` get `astinus:origin:base-level` (integer string)
  + `astinus:origin:base-ref` (claiming level's ImageRef).
  S6-T4 is visibility-only: the chain layer does NOT override
  Origin classifications, only annotates them. The strict-override
  mode + complete `AddedPackages` curation toolchain
  (`scripts/update-known-bases.go`) land in Sprint 7. See ADR-0061.

- **Actionable `--base auto` FallbackReason on unknown bases.**
  Pre-S6 the no-match diagnostic was a bare
  `"no known base for X Y"` blurb. Post-S6 the SBOM-stamped
  `astinus:basediff:detection-fallback-reason` lists the catalogued
  distros (and known versions for the detected distro, when the
  distro itself IS catalogued) plus the remediation hint
  (`Refresh the bundled snapshot … or supply --base <ref>
  explicitly`). Two new `KnownBases` helpers — `UniqueDistroIDs()`
  and `VersionsForDistro(id)` — drive the diagnostic and remain
  available for future CLI surfaces. ADR-0060.

- **Sprint 5 Phase A acceptance suite (`test/acceptance/sprint5/`).**
  Ten in-process tests across two sub-suites (`quality/`, `ux/`)
  pin every Sprint 5 Phase A task's operator-facing contract via
  the actual `astinus enrich` binary: stdlib CPE keep-primary +
  non-stdlib still evidence-only (T0), SONAME-derived
  `pkg:generic/<sonamename>` phantoms stay off the SBOM and
  library-shaped paths surface as observed-only (T1),
  `astinus:layer:digest` carries the OCI rootfs diff_id distinct
  from `astinus:layer:compressed-digest` + round-trips across a
  re-read/re-enrich (T2), buildinfo version wins over Syft at a
  different version + same-version overlap keeps the Syft
  breadcrumb (T3), `--cpe-mode offline` emits reason-encoded
  `:offline-mode` skipped entries + `--cpe-mode auto` populates
  `sources-used` + the `--help` text documents the three-state
  contract (T4). Build tag `acceptance`; full suite hermetic +
  ≈ 35 s wall-clock on M-class arm64. Pinned-Grafana real-image
  bundle (`gap_closure_rate ≥ 0.95` / `addition_precision ≥ 0.85` /
  `golang FPs ≤ 5` / `layer:digest sample accuracy ≥ 17/20`
  metric gates, Grype delta tests, multi-image anti-overfit gate)
  explicitly deferred to a Sprint 6 follow-up — documented in
  `test/acceptance/sprint5/fixtures/README.md`. (ADR-0052,
  S5 Task 5.)

### Changed

- **`--cpe-mode` contract finalised + observability widened.**
  The three modes (`offline` / `auto` / `hybrid`, with `online`
  as a deprecated alias for `hybrid`) get a full
  four-clause help-text rewrite explaining what each does and
  what fails how. New `astinus:cpe:sources-used` SBOM metadata
  property carries the comma-separated list of CPE sources that
  actually ran (`pattern-matcher`, `local-dict`, `online-nvd`,
  `clearly-defined`, `heuristic`). The existing
  `astinus:cpe:sources-skipped` property now uses
  `<source>:<reason>` per entry (e.g.
  `online-nvd:no-NVD_API_KEY`, `online-nvd:offline-mode`,
  `clearly-defined:offline-mode`) so SBOM consumers can tell
  apart graceful-degradation skips from offline-mode
  configuration choices without parsing logs. The
  S4-Task-4-introduced bare format (`online-nvd`) is gone —
  tools that pattern-matched on the exact token need to adapt
  to the reason-encoded shape. (ADR-0051, S5 Task 4.)

### Fixed

- **Go module versions resolve to `debug/buildinfo`, not
  Syft-inherited go.mod/go.sum.** Syft's `go-mod-cataloger`
  parses source files (intended dependencies) which can drift
  from the version actually compiled into the binary because of
  replace directives, vendor selection, or build-cache reuse.
  Run #3 benchmark on the Grafana digest measured 16 of 19
  golang FPs originating from this Syft-vs-buildinfo
  divergence (e.g. Syft said `getkin/kin-openapi @ v0.133.0`,
  the binary actually has `v0.134.0`). Dedup now drops the
  Syft-inherited row when an Astinus buildinfo row exists for
  the same module path at a different version. Same-version
  overlap (S4-T1 contract: buildinfo primary + Syft breadcrumb
  merged in) is preserved. (ADR-0050, S5 Task 3.)

### Changed

- **`astinus:layer:digest` now emits the OCI rootfs `diff_id`**
  (sha256 of the uncompressed tar — the canonical layer
  identifier per the OCI image-spec). Previous builds emitted a
  third hash — neither rootfs diff_id nor manifest compressed
  digest — that downstream consumers could not map to any layer
  in the image manifest. Run #3 benchmark measured sample
  accuracy 0/20 against ground-truth diff_ids; Sprint 5 Task 5
  pins the post-fix metric ≥ 17/20. Added
  `astinus:layer:compressed-digest` as a supplementary property
  carrying the manifest blob hash for tools that need it. The
  typed `model.LayerInfo` struct gains `LayerCompressedDigest`
  alongside the existing `LayerDigest`. CycloneDX + SPDX
  mappers round-trip both fields. (ADR-0049, S5 Task 2.)

### Fixed

- **Eliminated remaining ~60 `pkg:generic/<sonamename>` phantom
  rows from the untracked enricher.** ADR-0038 (S4 Task 0)
  kept DT_SONAME as the one ELF identity signal worth trusting;
  the run-#3 benchmark on a real Grafana image proved that
  assumption wrong. `libcrypto.so.3` → SONAME → `crypto` doesn't
  tell us whether the binary is OpenSSL, LibreSSL, BoringSSL,
  AWS-LC, or wolfSSL — every option ships the same SONAME.
  Resulting `pkg:generic/crypto`, `pkg:generic/cap`,
  `pkg:generic/cares`, `pkg:generic/brotlicommon`,
  `pkg:generic/brotlidec`, `pkg:generic/iconv`,
  `pkg:generic/curl` (and ~50 others) didn't match anything in
  NVD and dragged `addition_precision` to 0.42 on the run-#3
  benchmark. `ELFLibraryExtractor.Extract` now returns empty
  Identity unconditionally; library-shaped paths surface as
  `astinus:evidence-level = observed` rows the same as
  executables already do. The right home for ELF library
  identity is the upstream package manager (apk / dpkg / rpm),
  which Syft already catalogs reliably. (ADR-0048, S5 Task 1.)

- **Restored primary CPE for Go standard library components.**
  The ADR-0042 per-ecosystem demotion was over-broad: it sent
  every `pkg:golang/*` row to `astinus:cpe:evidence`, including
  `pkg:golang/stdlib@*` where the inherited CPE is
  `cpe:2.3:a:golang:go:<version>` — a registered NVD identifier
  with 351 CPE-aliased entries. The Grafana run-#3 benchmark
  measured a net Grype-match delta of **−19 vs Syft baseline**,
  losing 22 Go-runtime CVE matches (11 distinct High/Medium
  CVEs across go1.25.9 + go1.26.2). The new `KeepPrimaryPurls`
  policy field carves a narrow exception for `pkg:golang/stdlib`;
  module-path rows (`go.uber.org`, `k8s.io`, `gopkg.in`,
  `cel.dev`, `modernc.org`, `go.opentelemetry.io`,
  `go.etcd.io`, `sigs.k8s.io`, `knative.dev`, `src-d`) stay
  evidence-only — verified 10/10 NVD-zero in run #3. Components
  on the exception path stamp `astinus:cpe:exception-applied =
  keep-primary` + `astinus:cpe:exception-rationale` for audit
  traceability. (ADR-0047, S5 Task 0.)

### Added

- **Sprint 4 acceptance suite (`test/acceptance/sprint4/`).**
  Seven in-process tests across two sub-suites (`quality/`,
  `ux/`) pin every Sprint 4 task's operator-facing contract via
  the actual `astinus enrich` binary: no-phantom rows (T0),
  golang CPEs as evidence-only with v-prefix stripped (T3),
  `--cpe-mode auto` skip-with-metadata + `--cpe-mode hybrid`
  exit-60 + `--cpe-mode online` deprecation warning (T4),
  content-based base detection from os-release + scratch
  fallback-reason stamp (T6). Build tag `acceptance`; full suite
  hermetic + ≈ 50 s wall-clock on M-class arm64. Pinned-Grafana
  real-image bundle (`gap_closure_rate` / `phantom_count` /
  Grype-delta metric gates) explicitly deferred to a Sprint 5
  follow-up — documented in `test/acceptance/sprint4/fixtures/README.md`.
  (ADR-0046, S4 Task 7.)

### Fixed

- **Sprint 4 Task 7 surfaced and fixed an exit-code clobbering
  bug.** `allEnrichers` was wrapping every error in
  `newExitError(ExitInvalidArgs=2, err)`, including the
  `ExitCPESourceUnavailable=60` exit code that
  `buildCPEEnricher` returns for the strict `--cpe-mode hybrid`
  fail-fast path. The S4 Task 4 acceptance test caught the
  collision; the fix preserves any pre-coded `*exitError`
  semantic code from the inner call instead of overwriting with
  exit 2. (ADR-0046, S4 Task 7.)

### Added

- **Content-based base-image detection.** `--base auto` (the
  default) now falls back to reading `/etc/os-release` (or
  `usr/lib/os-release` / `etc/alpine-release`) when the target
  image carries no `org.opencontainers.image.base.*` labels —
  which is true of ~80 % of public Docker Hub images (Grafana,
  Postgres, Redis, Nginx, MongoDB, MySQL, Apache, Tomcat, …).
  The parsed OS-release identity is matched against a bundled
  `data/known_bases.json` catalogue (15 entries on initial ship:
  alpine 3.18-3.23, debian 11-12, ubuntu 20.04-24.04, almalinux
  9, rocky 9, RHEL UBI 9, distroless base-debian12). Detection
  outcome stamps `astinus:basediff:detection-method`,
  `astinus:basediff:detected-base`,
  `astinus:basediff:detection-confidence`,
  `astinus:basediff:os-release-id`,
  `astinus:basediff:os-release-version-id`, and (on a no-detection
  outcome) `astinus:basediff:detection-fallback-reason` on
  `sbom.Metadata.Properties` so downstream consumers can branch
  on the result without parsing logs. Label-based detection still
  runs first and short-circuits the pipeline at 1.0 confidence
  when labels are present. (ADR-0045, S4 Task 6.)

### Fixed

- **Oversize files no longer abort the untracked walk.** A single
  file over `MaxFileBytes` used to kill the entire untracked
  enricher with `untracked: file exceeds MaxFileBytes`, which on
  Trivy CDX input — where the binary lacks a Syft-style skip-set
  entry — broke `astinus enrich --sbom trivy.cdx.json` on any
  image with a Go binary over the cap (e.g. Grafana's 435 MB
  single-binary distribution). The walk now records the file as
  an observed-only Component carrying
  `astinus:untracked:skipped-reason = file-exceeds-max-bytes`
  plus the active cap and the header-declared file size, then
  continues. Operators see the gap in the SBOM rather than a
  failed run. (ADR-0044, S4 Task 5.)

### Changed

- **`DefaultMaxFileBytes` raised from 256 MiB → 2 GiB.** The
  pre-S4 ceiling was calibrated against synthetic Stage-4
  fixtures and tripped on real-world Go / JVM / native-app
  binaries. The 2 GiB default covers every binary observed on
  public images while leaving margin before pathological
  multi-GB blobs hit the cap. Operators on memory-constrained CI
  runners can still lower the cap via the existing
  `Options.MaxFileBytes` field. (ADR-0044, S4 Task 5.)

### Added

- **SBOM input-source detection.** `model.DetectSource(sbom)`
  returns `SourceSyft`, `SourceTrivy`, `SourceOther`, or
  `SourceUnknown` by case-insensitive substring matching
  `sbom.Metadata.Tools[].Name` / `.Vendor`. The pipeline logs
  the detected source once per run (`pipeline.input.source`) so
  operators see which upstream tool produced the SBOM they fed
  in. Informational today; future enrichers will be able to
  branch on it. (ADR-0044, S4 Task 5.)

### BREAKING

- **`--cpe-mode` default changed from `hybrid` to `auto`.** The
  pre-S4 `hybrid` default silently dropped unavailable online
  sources (the rate-limit graceful degradation from ADR-0028).
  That behaviour now lives under the new `auto` value, which is
  the default. Explicit `--cpe-mode hybrid` is now strict — it
  exits **60** when an expected online source is unavailable
  (typically NVD without an API key on a workload that would
  exceed the anonymous rate limit). `--cpe-mode online` is a
  deprecated alias for `hybrid` (DeprecationWarning logged; will
  be removed in v1.0.0). Operators who relied on the pre-S4
  silent-degradation should either remove the explicit flag (auto
  is the new default) or pass `--cpe-mode auto`. CI gates that
  want the strict behaviour can pass `--cpe-mode hybrid` and add
  exit code 60 to their known set. (ADR-0043, S4 Task 4.)

### Added

- **Exit code 60 (`ExitCPESourceUnavailable`).** Emitted when
  `--cpe-mode hybrid` (or the deprecated `online` alias) cannot
  enable a required online source. The error message lists the
  unavailable source and the resolution options (set
  `NVD_API_KEY`, switch to `--cpe-mode=auto`, or switch to
  `--cpe-mode=offline`). (ADR-0043, S4 Task 4.)
- **SBOM-level CPE-mode metadata.** Every Astinus-enriched SBOM
  now carries `astinus:cpe:mode` (the effective mode: `auto`,
  `hybrid`, `offline`) and, when degradation fired,
  `astinus:cpe:sources-skipped` (comma-separated list of dropped
  source IDs — today only `online-nvd`). SBOM consumers like
  Dependency-Track can branch on these to tell apart full-online
  enrichment from a degraded-auto run without parsing logs.
  (ADR-0043, S4 Task 4.)

### Fixed

- **Go-module CPEs no longer create misleading scanner match
  surface.** A real-image audit found 0/10 sampled Go-module CPEs
  matched anything in NVD: the vendor names (`go.uber.org`,
  `k8s.io`, `gopkg.in`, `cel.dev`, `modernc.org`, …) are
  module-path TLDs NVD does not register, and 77 % carried a
  `:vX.Y.Z:` version where NVD's CPE dictionary stores `:X.Y.Z:`.
  The new per-ecosystem CPE policy strips the `v` prefix on Go
  rows and demotes the row's primary CPE to
  `astinus:cpe:evidence` plus `astinus:cpe:scope = evidence-only`
  and a rationale property. The candidate stays in the SBOM for
  audit but no longer expands the scanner's match surface with
  un-indexable coordinates. npm / pypi / maven / deb / rpm / apk
  rows are unchanged. (ADR-0042, S4 Task 3.)

### Added

- **`internal/enrich/cpe/policy.go` — per-ecosystem CPE policy.**
  `EcosystemPolicy{EmitPrimary, EvidenceOnly, NormalizeVersion,
  RejectVendors, Rationale}` data table consumed by the CPE
  enricher's `writeResults`. `DefaultPolicies()` ships the
  Grafana-audit-driven defaults (`golang` evidence-only with a
  hand-curated RejectVendors list; everything else primary).
  Operator overrides via the new `Enricher.WithPolicies` hook;
  a CLI `--cpe-policy <file>` surface is deferred to a
  follow-up. (ADR-0042, S4 Task 3.)

### Fixed

- **Layer attribution now lands on Syft-tracked package
  components.** Syft's apk / dpkg / rpm catalogers stamp the
  binary path on `Properties["syft:location:N:path"]` (and the
  layer digest on `syft:location:N:layerID`), not on
  `Evidence.Locations`. The attribution enricher's stamper now
  reads both sources after its existing Evidence.Locations
  pass, plus a direct `layerID` → `FileMap.Layers()` match for
  squashed/normalised image cases where the path lookup fails.
  Real-image fallout: previously 0 / 573 ground-truth-matching
  packages carried `astinus:layer:digest` on Grafana; the fix
  unblocks coverage to the Task 7 acceptance threshold.
  (ADR-0041, S4 Task 2.)
- **Go module deps from buildinfo now reach the output SBOM on
  real production images.** The extractor enricher previously
  consulted only `Component.Evidence.Locations` to find binaries
  to walk; Syft's apk / dpkg / rpm catalogers stamp the binary
  path on `Properties["syft:location:N:path"]` instead, so the
  extractor walk silently skipped every package-managed Go
  binary. Real-image fallout: 0 Go modules added on top of Syft
  on a Grafana image with 547 embedded module records. Fix:
  `knownPathsForComponent` now harvests both shapes, matching
  the untracked enricher's known-paths skip-filter (ADR-0040,
  S4 Task 1).
- **`(devel)` Go module versions no longer trigger every-CVE
  false-positives in downstream scanners.** The PURL renderer now
  emits `pkg:golang/<path>?vcs_ref=devel` for in-tree builds,
  carrying the "no resolvable version" signal in a PURL-spec
  qualifier instead of as a literal `@(devel)` version. (ADR-0040,
  S4 Task 1.)
- **Dedup primary-pick respects evidence level.** A
  buildinfo-grounded `type=library` row at PURL `pkg:golang/x@v1`
  no longer loses to a Syft `type=file` row at the same PURL when
  both appear in the SBOM. New scoring band (+50 for
  `evidence-level = identified`, +5 for non-`file` types) plus a
  one-way type ratchet (`file` → `library`/`application`) keeps
  the merged Component on the strongest identity. (ADR-0040,
  S4 Task 1.)

### Added

- **`astinus:layer:source` component property** records which
  discovery path produced the layer attribution:
  `filemap-last-touch` (Evidence.Locations vs FileMap),
  `syft-location-property` (translated from Syft's per-component
  property bag), or `preexisting` (LayerInfo already set by an
  upstream enricher like the Go-buildinfo path). Operators
  building coverage dashboards can grep this property without
  parsing every layer-property to learn provenance. (ADR-0041,
  S4 Task 2.)

### Changed

- **Go module `Component.Version` no longer carries the `v`
  prefix.** Tagged releases stored as `1.2.3`, pseudo-versions as
  `0.0.0-20231212003515-deadbeefcafe`, `+incompatible` suffixes
  preserved verbatim. The PURL keeps the `v` prefix because the
  purl-spec golang type and the Go module proxy both require it.
  Operators with `version >= X` policy expressions can now write
  them against Go rows without a Go-aware comparator. (ADR-0040,
  S4 Task 1.)
- **Lifted SubComponents (Go modules, Rust crates, Java
  manifests, Python dist-info, ELF SONAMEs) carry identity
  provenance stamps.** Every lifted dep now records
  `astinus:evidence-level = identified`, `astinus:identified:source
  = go-buildinfo` (or the equivalent per source), and
  `astinus:extractor:embedded-in-path = <full path>` so
  forensic queries on the SBOM don't require walking the
  relationships graph. (ADR-0040, S4 Task 1.)

### Removed

- **Filename-only identity heuristics in the untracked enricher.**
  The ELF extractor no longer falls back to `basename(file.Path)`
  when `DT_SONAME` is absent; the PE extractor's
  `name-1.2.3.exe` filename guess is gone; the JAR extractor's
  third-tier filename fallback (`commons-lang3-3.14.0.jar`) is
  gone. On a real Grafana image these paths fabricated **77
  phantom `pkg:generic/<basename>` components** (`busybox`,
  `crypto`, `c_rehash`, `ssl_client`, …) that then attracted
  18 false-positive CVE matches in Grype. None of them
  corresponded to real packages. (ADR-0038, S4 Task 0.)

### Added

- **`astinus:evidence-level` component property.** Every
  Component now carries either `identified` (verifiable
  metadata — buildinfo, signed manifest, dist-info record, or
  a fingerprint-matcher hit) or `observed` (we recorded the
  file's path / SHA-256 / layer but cannot make a
  package-identity claim). Surfaced as a property and as the
  `model.EvidenceLevel` typed field. Lets policy frameworks,
  vulnerability scanners, and audit reviewers branch on
  evidence strength explicitly. (ADR-0038, S4 Task 0.)

### Fixed

- **Phantom CVE matches sourced from untracked enrichment.** On
  the Sprint-4 reproducer image, Grype no longer reports
  `pkg:generic/busybox@1.0`-attributed CVEs that originated
  inside Astinus rather than inside the image. (ADR-0038,
  S4 Task 0.)
- **`untracked` Component schema for unidentified files.**
  Files the multi-modal extractor registry cannot identify are
  now emitted with `Type = file`, `Name` = full path,
  empty PURL / CPE / version, plus the SHA-256 hash and layer
  digest. Earlier revisions emitted `Type = application`,
  `Name` = basename, which made the row look like a package
  claim to downstream scanners. (S4 Task 0.)

## v0.0.1 — 2026-05-05 (first public release)

This is the first public tag. It bundles three internal
development sprints — Hardening Sprint #1, Production Readiness
Sprint #2, and Real-World Enrichment Sprint #3 — into a single
coherent release. The detailed per-sprint changelogs are
preserved verbatim under [Pre-1.0 sprint logs](#pre-10-sprint-logs-for-archaeology)
below.

### Highlights

- **Layer attribution** — every component carries the layer
  digest, layer index, and Dockerfile instruction (`RUN` / `COPY`
  / `ADD`) that introduced it.
- **Base-image diff** — components are split into `base` /
  `app` / `unknown`. Auto-detects the base image from OCI
  labels; content-addressable Tier 1 strategy handles squashed
  and multi-stage images.
- **Untracked-component detection** — vendored binaries / archives
  / scripts that no package manager tracks. Multi-modal extractor
  registry (Go buildinfo, Rust `.dep-v0`, Java POM/manifest,
  Python METADATA, ELF, PE) lifts embedded modules into top-level
  components with `RelationshipDependsOn` edges.
- **Multi-runtime matrix** — Docker, BuildKit (with provenance
  attestation round-trip), Podman, Buildah, Kaniko.
- **CPE enrichment** — bundled dictionary (~217 entries) +
  per-PURL-type heuristic + NVD API source with token-bucket
  rate-limit. Online / offline / hybrid modes; `--no-network`
  forces offline. Per-Candidate confidence scoring; hardware-
  CPE-on-software-PURL hard-rejected (closes the v0.2 yq → Linksys
  router false positive).
- **Package-registry metadata** — license / supplier / homepage /
  repository fetched from npm, PyPI, Maven Central, and the Go
  module proxy. Adapters for cargo / RubyGems / NuGet / Debian /
  Alpine / Repology / ecosyste.ms are stub-registered (return
  `ErrNotFound` — components from those ecosystems pass through
  unchanged); tracked under the [`registry-source`](https://github.com/psyf8t/astinus/issues?q=label%3Aregistry-source)
  label.
- **Lifecycle / EOL annotations** — runtime and OS components
  (Node, Python, Go, Java, Debian, Ubuntu, Alpine, Postgres, MySQL,
  Redis, Kubernetes, Docker, …) get `astinus:lifecycle:status` /
  `:eol` / `:active-support-end` from
  [endoflife.date](https://endoflife.date) plus a bundled offline
  snapshot.
- **Compliance validators** — NTIA Minimum Elements + EU CRA
  Article 13. Per-ecosystem severity policy keeps the noise
  manageable; `--fail-on <severity>` exits 40 when findings cross
  the gate.
- **Cosign signing** — `--sign-with cosign-key` or `cosign-keyless`
  produces detached signatures or in-toto attestations attached to
  an OCI image. New top-level `astinus verify` subcommand wraps
  `cosign verify-blob` + `cosign verify-attestation`. Subprocess
  approach keeps the binary at ~12 MiB (sigstore-go would have
  pushed it past 60 MiB).
- **Corporate environment support** — HTTP/HTTPS proxy via env,
  per-mirror config (replace + fallback modes, bearer / basic /
  custom-header auth, mTLS client cert, custom CA bundle),
  air-gapped `--no-network` mode with an offline catalogue layout
  and bundled lifecycle snapshot.
- **Acceptance suite** — both the Sprint 3 in-process suite
  (~22 s, no docker required) and the PRSD-Task-9 image / scanner
  / runtime / validator matrix (~30 min, docker + tooling
  required). Total: 19 in-process tests + 8 image-type tests + 5
  runtime tests + 3 scanner tests + 3 validator tests +
  performance benchmarks for 1 GB / 5 GB / memory / Sprint 3
  enrichment paths.

### Output formats

- **Read:** CycloneDX 1.5 and 1.6 (JSON, XML); SPDX 2.2 and 2.3
  (JSON, tag-value).
- **Write:** CycloneDX 1.6 (JSON, XML); SPDX 2.3 (JSON, tag-value);
  SARIF 2.1.0 (GitHub Code Scanning ready); plain-text summary.

### Compatibility

- Go ≥ 1.25.9 to build from source. The bundled binaries cover
  linux / darwin / windows × amd64 / arm64.
- Distroless container image at `ghcr.io/psyf8t/astinus:v0.0.1`
  (multi-arch).
- Release artifacts are signed via Cosign keyless (Sigstore
  public). The release page footer carries the verification
  command.

### Known gaps for v0.0.1

- 7 of 11 registry sources are stubs — see the [`registry-source`](https://github.com/psyf8t/astinus/issues?q=label%3Aregistry-source)
  label for the open work items. Components from those
  ecosystems still get layer / CPE / lifecycle enrichment; only
  the package-metadata fetch is a no-op.
- Architecture Decision Records are kept in `docs/adr/` but the
  directory is currently `.gitignore`d; the public ADR layout is
  an open question — see [docs: decide on public ADR layout](https://github.com/psyf8t/astinus/issues?q=label%3Adocumentation+ADR).
  CHANGELOG references like `ADR-0036` will become live links
  once the layout is settled.
- No Helm chart yet (Stage 15 deliverable).
- No GitHub Action wrapper yet (Stage 15 deliverable).

### Migration / upgrade

This is the first public release. Nothing to migrate.

---

## Pre-1.0 sprint logs (for archaeology)

The detailed sprint-by-sprint changelogs from internal
development. Preserved verbatim because they're useful for
bisecting, blame-archaeology, and understanding *why* a given
behaviour exists.

## Sprint 3 — Real-World Enrichment

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

## Sprint 2 — Production Readiness (internal pre-release v0.2.0, 2026-05-03)

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

## Sprint 1 — Hardening

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
