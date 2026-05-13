# Sprint 6 acceptance fixtures

The Sprint 6 acceptance suite (`go test -tags acceptance
./test/acceptance/sprint6/...`) pins each Sprint 6 task's
operator-facing contract via the actual `astinus enrich`
binary. Each test synthesises its own OCI layout + input SBOM
at test time, so the fixtures directory stays empty for now.

## Deferred: 4-image pinned-digest bundle

The Sprint 6 Task 9 spec
(`docs/private/sprint6/task_9_multi_image_acceptance.md`)
sketches a comprehensive multi-image bundle:

- **A-grafana** — `grafana/grafana@sha256:081a24a2…`
  (Go-heavy, Alpine 3.23.x)
- **B-airflow** — `apache/airflow:slim-latest@sha256:5fee7d30…`
  (Python, Debian Bookworm)
- **C-nginx** — `nginx:stable-alpine@sha256:06f3c38d…`
  (minimal apk, Alpine)
- **D-postgres** — `postgres:17@sha256:b0747e5d…`
  (deb-heavy, Debian Trixie)

Each slot carries `digest.txt`, `syft.cdx.json`,
`trivy.cdx.json`, `ground-truth.json` (per-image package
manifest with ecosystem + version + Origin), `manifest.json`
(OCI manifest snapshot), and an `oci/` layout — totalling
~3-5 GB uncompressed / ~1.5 GB compressed.

This bundle is **deferred to a Sprint 7 follow-up** because:

1. Committing four OCI layouts adds ~1.5 GB compressed to the
   repo. Git LFS or a release-asset hosting story (the task
   spec sketches `make fetch-acceptance-fixtures` against per-
   image GitHub Release artifacts) is its own task. The same
   trade-off Sprint 5 Task 5 made for the single-image
   pinned-Grafana bundle (see ADR-0052 / Sprint 5
   `fixtures/README.md`) compounds here.
2. Generating the ground-truth JSON requires the
   `apk-db + dpkg-status + package.json + go-version -m`
   toolchain plus access to each live image — that's a
   fixture-refresh subsystem (`update_fixtures/update.go`
   sketched in the task spec).
3. The Sprint 6 hardening fixes (T0–T5) and Stage 14 features
   (T6–T8) are each pinned by in-process synthetic tests in
   this suite **plus** the per-package unit tests of the
   affected modules. The metric-level pins against the pinned
   digests (e.g. `TestAirflow_OriginAccuracy ≥ 0.85`,
   `TestNginx_GrypeNetTPDeltaZero`,
   `TestPostgres_NoUrlPercentInCPEs`) are the natural Sprint
   7 work alongside the refresh toolchain.

## What the synthetic gates cover today

| Sub-suite | Test file | Pins | Sprint 6 task |
|---|---|---|---|
| quality | `cpe_walltime_test.go` | `--cpe-mode auto` + 10-component hung-server SBOM exits ≤ 5 s with partial output + total-cap stamp | T0 |
| quality | `cpe_encoding_test.go` | Debian-epoch versions backslash-escape (`\:`, `\+`); no `%xx` URL-percent | T1 |
| quality | `apk_earliest_test.go` | apk-managed components on multi-apk-add image carry `astinus:layer:source = apk-earliest-layer` + correct layer index | T2 |
| quality | `trixie_fallback_test.go` | Synthetic Debian 13 image resolves `debian:trixie-slim` + actionable `FallbackReason` on unknown distro | T3 |
| quality | `layered_chain_test.go` | python:slim-bookworm chain → `astinus:basediff:chain:0=python:3.13-slim-bookworm` + `chain:1=debian:bookworm-slim` | T4 |
| quality | `alt_cpe_test.go` | Multi-`syft:cpe23` busybox row preserves 4+ alternatives + `:alternatives-count` stamp | T5 |
| features | `vex_suppress_test.go` | OpenVEX `not_affected` suppresses CVE compliance finding + stamp lands | T6 |
| features | `policy_deny_test.go` | YAML policy `deny` matching component PURL emits `LICENSE`-style synthetic finding → `--fail-on high` exits 40 | T7 |
| features | `license_gate_test.go` | `--license-deny GPL-3.0-only` on a mixed-license SBOM exits 40 + per-violation stamp | T8 |
| features | `stage14_composition_test.go` | VEX + policy + license run end-to-end on one SBOM without breaking each other | T6+T7+T8 |

The deferred bundle adds 33 hardening gates (per-image metric
pins against the 4 pinned digests) + 4 aggregate gates
(park-wide variance + Grype TP delta + URL-percent absence)
— each measures a metric against a pinned image; each needs
the OCI layout + ground truth this directory doesn't carry
yet.

## Update workflow (when the bundle lands)

Sketch only — the actual `update.go` script ships with the
fixtures themselves:

```sh
# In the Sprint 7 follow-up:
go run ./test/acceptance/sprint6/update_fixtures/update.go \
    --slot A-grafana --digest grafana/grafana@sha256:NEW_DIGEST \
    --platform linux/arm64

# Per-image bundle artifact for the GitHub Release:
make fetch-acceptance-fixtures SLOT=A-grafana
```

## What this directory contains today

This README. Synthetic gates live in `../quality/` and
`../features/` and don't read from this directory.
