# Sprint 4 acceptance fixtures

The Sprint 4 acceptance suite (`go test -tags acceptance ./test/acceptance/sprint4/...`)
pins Sprint 4 task behaviour against regression. Most tests build
their own minimal OCI image at test time via
`helpers.OCIImageWithFiles` and SBOM input via `helpers.WriteCDXSBOM`,
so the fixtures directory stays empty for now.

## Deferred: pinned-Grafana real-image fixture

The Sprint 4 task spec (`docs/private/sprint4/task_7_real_image_acceptance.md`)
sketches a pinned-digest Grafana fixture set:

- `grafana-digest.txt` — `grafana/grafana@sha256:2d1f9ae6…` pin.
- `grafana-syft.cdx.json` / `grafana-trivy.cdx.json` — baseline SBOMs.
- `grafana-ground-truth.json` — 611 ground-truth components
  (34 apk + 14 npm + 563 Go modules) for `gap_closure_rate` /
  `addition_precision` metric tests.
- `grafana-oci/` — committed OCI layout for the pinned image.

This bundle is **deferred to a Sprint 5 follow-up** because:

1. Committing the OCI layout would add ~1 GB to the repo (the
   Grafana image is ~435 MB uncompressed plus indices). Git LFS
   or a release-asset hosting story belongs in its own task.
2. Regenerating the ground-truth JSON requires the
   `apk-db + package.json + go-version -m` toolchain plus access
   to the live image — that's a fixture-refresh subsystem, not a
   one-task add.
3. The Sprint 4 task fixes (T0–T6) are each pinned by
   in-process synthetic tests in this suite + the unit suites of
   the affected packages. Metric-level pinning (`gap_closure_rate
   ≥ 0.50`, `phantom_count == 0` on the real digest) is the
   natural Sprint 5 follow-up alongside the refresh toolchain.

## Update workflow (when the Grafana fixtures land)

Sketch only — the actual `update.go` script ships with the
fixtures themselves:

```sh
# In a follow-up sprint:
go run ./test/acceptance/sprint4/update_fixtures/update.go \
    --digest grafana/grafana@sha256:NEW_DIGEST \
    --platform linux/arm64

git status
# All grafana-*.{txt,json} regenerated together — partial refresh
# is rejected by the script.
```

## What this directory contains today

Nothing. The presence of the directory + this README is the
explicit handoff to the Sprint 5 task that builds the real-image
gate.
