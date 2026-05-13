# Sprint 5 acceptance fixtures

The Sprint 5 Phase A acceptance suite (`go test -tags acceptance
./test/acceptance/sprint5/...`) pins each Phase A task's
operator-facing contract via the actual `astinus enrich`
binary. Each test synthesises its own OCI layout + SBOM input
at test time, so the fixtures directory stays empty for now.

## Deferred: pinned-Grafana real-image bundle

The Sprint 5 Task 5 spec
(`docs/private/sprint5/task_5_real_image_acceptance.md`) sketches
a comprehensive real-image bundle:

- `grafana-digest.txt` —
  `grafana/grafana@sha256:2d1f9ae6…` pin.
- `grafana-syft.cdx.json` /
  `grafana-trivy.cdx.json` — baseline SBOMs from the pinned image.
- `grafana-ground-truth.json` — 611 ground-truth components
  (34 apk + 14 npm + 563 Go modules) so the metric gates
  (`gap_closure_rate ≥ 0.95`, `addition_precision ≥ 0.85`,
  `golang FPs ≤ 5`, `layer:digest sample accuracy ≥ 17/20`)
  have something to measure against.
- `grafana-oci/` — committed OCI layout for the pinned image.
- `grafana-manifest.json` — OCI manifest snapshot for layer
  digest expectations.

This bundle is **deferred to a Sprint 6 follow-up** because:

1. Committing the OCI layout adds ~1 GB to the repo (the
   Grafana image is ~435 MB uncompressed plus indices and
   blobs). Git LFS or a release-asset hosting story is its
   own task — the Sprint 5 Task 5 spec actually documents
   this as an "Open question" alongside the suite design.
2. Generating the ground-truth JSON requires the
   `apk-db + package.json + go-version -m` toolchain plus
   access to the live image — that's a fixture-refresh
   subsystem (also discussed in the task spec under
   `update_fixtures/`).
3. The Sprint 5 Phase A task fixes (T0–T4) are each pinned by
   in-process synthetic tests in this suite **plus** the
   per-package unit tests of the affected modules. The
   metric-level pin against the real Grafana digest is the
   natural Sprint 6 work alongside the refresh toolchain and
   the multi-image (Task 9, airflow / vllm) anti-overfit
   gate.

## What the synthetic gates cover today

| Test file | Pins | Sprint 5 task |
|---|---|---|
| `quality/stdlib_cpe_test.go` | `pkg:golang/stdlib` keeps primary CPE + `astinus:cpe:exception-applied=keep-primary` | T0 |
| `quality/no_phantom_test.go` | No `pkg:generic/<sonamename>` rows from library-shaped paths | T1 |
| `quality/layer_digest_test.go` | `astinus:layer:digest` carries the OCI rootfs diff_id; `astinus:layer:compressed-digest` is the distinct manifest blob hash | T2 |
| `quality/go_module_version_test.go` | Buildinfo row wins over Syft-inherited row at a different version | T3 |
| `ux/cpe_mode_test.go` | `astinus:cpe:sources-used` populated; `astinus:cpe:sources-skipped` carries `<source>:<reason>` shape | T4 |

The deferred Grafana metric gates would add 12+ more tests
(`TestGapClosureGolang`, `TestAdditionPrecision`,
`TestGolangFPsBelowThreshold`,
`TestLayerDigestSampleAccuracy`,
`TestPackageLayerAttributionCoverage`,
`TestBaseAutoDetectsAlpine`, three Grype-delta tests, plus
the Sprint 3 + Sprint 4 regression gates). Each measures a
metric against the pinned digest; each needs the OCI layout +
ground truth this directory doesn't carry yet.

## Update workflow (when the bundle lands)

Sketch only — the actual `update.go` script ships with the
fixtures themselves:

```sh
# In the Sprint 6 follow-up:
go run ./test/acceptance/sprint5/update_fixtures/update.go \
    --digest grafana/grafana@sha256:NEW_DIGEST \
    --platform linux/arm64

git status
# All grafana-*.{txt,json} regenerated together — partial refresh
# is rejected by the script.
```

## What this directory contains today

This README. Synthetic gates live in `../quality/` and
`../ux/` and don't read from this directory.
