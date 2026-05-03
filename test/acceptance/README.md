# Acceptance test suite

This directory holds Astinus's PRSD-Task-9 acceptance suite — the
final-validation layer that verifies the production-readiness gates
the Sprint set out to meet. It is **not** part of the default
`go test ./...` run (the tests build only under `-tags acceptance`
or `-tags benchmark`) so contributors don't need a docker daemon
to land changes.

## Layout

```
test/acceptance/
├── helpers/      shared docker/exec wrappers + SBOM probes
├── images/       8 image-type acceptance tests (one *_test.go each)
├── validators/   external SBOM validators (cyclonedx-cli, pyspdxtools, bomctl)
├── scanners/     vuln scanners (grype, osv-scanner, trivy)
└── runtimes/     5-runtime matrix (docker / buildkit / podman / buildah / kaniko)

test/benchmarks/  perf gates (1 GB / 5 GB / memory peak)
```

## Running locally

The fastest path is running the image suite against a docker daemon
you already have:

```sh
go test -tags acceptance -v -timeout 30m ./test/acceptance/images/...
```

Each test calls `helpers.RequireDockerDaemon` (and per-tool
`helpers.RequireCommand`); missing prerequisites turn into
`t.Skip` so the suite degrades gracefully on a half-configured
machine.

The benchmarks live behind their own tag and use the standard
`-bench` flag:

```sh
go test -tags benchmark -bench=. -benchtime=1x -timeout 50m ./test/benchmarks/...
```

## CI

`.github/workflows/acceptance.yml` runs the same five jobs nightly
(04:00 UTC) and on `workflow_dispatch`:

- `images`   — installs syft, runs the 8 image-type tests
- `validators` — installs cyclonedx-cli + pyspdxtools + bomctl
- `scanners` — installs grype + osv-scanner + trivy
- `runtimes` — matrix over docker / buildkit / podman / buildah
- `benchmarks` — perf gates

The matrix intentionally omits Kaniko — Kaniko ships as a container
image rather than a host binary, so the test gates itself with
`helpers.CanRunKaniko()` and skips on stock GitHub runners. Add a
self-hosted runner with Kaniko's `executor` on PATH to enable.

## What each track verifies

| Track | What it asserts | Where |
|---|---|---|
| **A — Compliance** | NTIA + EU CRA validators report 0 critical findings | every `images/*_test.go` |
| **B — Vuln scanning** | Grype / OSV / Trivy all find CVE-2021-44228 in the same log4j-2.14.1 image | `scanners/*_test.go` |
| **C — Attribution** | Origin coverage ≥ 90%, runtime detected per builder, 0 dups | `images/*_test.go` + `runtimes/*_test.go` |
| **Perf** | 1 GB < 2 min, 5 GB < 8 min, peak memory < 4 GiB | `test/benchmarks/*` |
| **Quality** | cyclonedx-cli + pyspdxtools + bomctl validate without error | `validators/*_test.go` |

## Adding a new image-type test

1. Drop a `<name>_test.go` under `images/` with the
   `//go:build acceptance` tag.
2. Use `helpers.BuildImage(t, dockerfile, extras)` to materialise
   the image (deterministic per-dockerfile tag → docker layer
   cache reuses across runs).
3. Use `helpers.GenSyftSBOM(t, img)` for the baseline SBOM.
4. Use `helpers.RunAstinusFull(t, opts)` to invoke the locally-
   built astinus binary; it returns a parsed `*cdx.BOM`.
5. Assert on the spec's track gates via the helpers
   (`GetNTIAFindings`, `ComputeCPECoverage`,
   `GetRuntimeProperty`, …).

## Failure investigation

When a gate trips, check `docs/private/acceptance-results.md` —
the maintained baseline numbers from the last clean run let you
tell "regressed by 2 percentage points" from "regressed by 50".

When a test that previously passed now skips, the prerequisite
went missing (docker stopped, syft fell off PATH, …); the
`t.Skip` message is the diagnostic.
