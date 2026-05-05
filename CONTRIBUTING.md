# Contributing to Astinus

Thanks for your interest. Astinus is pre-1.0; this guide will get
more formal as v1.0 approaches.

## Most useful contributions right now

- **Real-world SBOMs that show gaps.** If Syft (or Trivy or cdxgen)
  emits an SBOM where Astinus misses something a human can see,
  that's gold. File it as a [coverage issue](https://github.com/psyf8t/astinus/issues/new)
  with the source SBOM (or a redacted version) attached.
- **Implementing one of the 7 stub registry sources.** Each is
  tracked under [`registry-source: <ecosystem>`](https://github.com/psyf8t/astinus/issues?q=label%3Aregistry-source).
  The issue body has the API reference, expected fields, and
  acceptance criteria.
- **Documentation.** If a doc page is unclear, file an issue or
  open a PR.
- **Naming things.** If you spot an awkward term in code or docs,
  propose a clearer one.

## Less useful right now

- Big architectural rewrites — the architecture is settled enough
  that a refactor PR without a tracking issue will likely sit.
  Open an issue first to discuss.
- New top-level features outside the
  [extension points](README.md#extensibility) — same reason.
  Discuss first.

## Development setup

Requirements:

- Go ≥ 1.25.9 (use the version in `go.mod`; the Makefile pins
  `GOTOOLCHAIN`)
- Docker (for the image acceptance tests; unit tests work without it)
- `golangci-lint` (`make tools` installs it)
- Optional: `cosign` (for the signing acceptance tests)

```bash
git clone https://github.com/psyf8t/astinus
cd astinus
make build
make test
make lint
```

## Running tests

- `make test` — unit tests with race detector
- `make test-integration` — integration suites (build tag: `integration`)
- `go test -tags acceptance ./test/acceptance/sprint3/...` —
  Sprint 3 in-process acceptance suite (~22 s, no Docker required)
- `go test -tags acceptance ./test/acceptance/images/...` — image
  acceptance suite (requires Docker daemon + Syft binary)

## Commit conventions

- Imperative mood (`add`, not `added`)
- Prefix with bracketed context where useful: `[stage-N]`,
  `[s3-task-N]`, `[release-prep-X]`, or skip the prefix for small
  changes
- One logical change per commit; rebase to clean up before opening
  a PR
- **No `Co-Authored-By: Claude` / AI footers.** Author your work
  honestly. Real human pair-programming attribution is welcome.

A `.gitmessage` template lives in the repo root and is registered
as `commit.template` automatically when you clone — your editor
will show the convention reminder when you `git commit`.

## PRs

- Open against `dev`, not `main` (we merge `dev → main` only on
  releases)
- One PR per concern
- Include test changes in the same PR as the code change they cover
- CI must be green before merge — the `Lint` and `Test` jobs are
  required

## Architecture decisions

Material decisions are recorded as ADRs (Architecture Decision
Records). Until the public ADR layout is settled (see
[issue: docs: decide on public ADR layout](https://github.com/psyf8t/astinus/issues?q=label%3Adocumentation+ADR)),
the `docs/adr/` directory stays internal. For a change that
warrants an ADR, file a discussion issue describing the decision —
maintainers will produce the ADR and link it from the next CHANGELOG
entry.

## License

By contributing, you agree your contribution is licensed under the
[Apache License 2.0](LICENSE), the same as the rest of the project.
