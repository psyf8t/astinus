---
name: Registry source — implement
about: Track implementation of a deferred package-registry adapter
title: 'registry-source: <ecosystem>'
labels: enhancement, registry-source, good-first-issue
---

## Ecosystem

<!-- e.g. cargo, RubyGems, NuGet, Debian, Alpine, Repology, ecosyste.ms -->

## Current state

The adapter is stub-registered in
`internal/enrich/registry/sources/stubs.go`. `Supports()` returns
true for the ecosystem, `Fetch()` returns `registry.ErrNotFound`,
and the resolver falls through to the next source.

This means components from this ecosystem **see no
license / supplier / homepage / repository enrichment** in v0.0.1.

## Implementation notes

- API endpoint: <!-- fill in -->
- Per-version metadata fields available: <!-- fill in -->
- Authentication required: <!-- yes / no -->
- Mirror conventions: <!-- e.g. Artifactory format, devpi, … -->
- See `internal/enrich/registry/sources/npm.go` for a reference
  adapter — same shape: `Supports`, `Fetch`, `Name`. Reuse the
  `MirrorChain` + `FetchJSON` plumbing in `fetch.go` rather than
  re-doing HTTP from scratch.

## Acceptance criteria

- [ ] Replace stub in `stubs.go` with a real adapter file
      (e.g. `cargo.go`)
- [ ] Unit tests cover: 200 happy path, 404 not-found, 5xx retry,
      malformed body, empty body
- [ ] Mirror config support (replace + fallback modes)
- [ ] Registry cache integration (memory + disk)
- [ ] Acceptance test in `test/acceptance/sprint3/enrichment/`
- [ ] CHANGELOG entry under the next release
