//go:build acceptance

// Package helpers carries the Sprint 6 acceptance suite's
// shared infrastructure. Like Sprint 5, the bulk of the helpers
// (binary builder, RunEnrichOK, OCIImageWithFiles, WriteCDXSBOM,
// FindComponent, PropertyValue, MetadataProperty) are reused from
// Sprint 3 and Sprint 4 directly; this package only adds the
// suite-specific glue when needed.
//
// Build tag: every file in this tree carries `//go:build
// acceptance` so the default `go test ./...` invocation skips
// them. CI invokes the suite explicitly:
//
//	go test -tags acceptance -v -timeout 5m ./test/acceptance/sprint6/...
//
// The full pinned-multi-image bundle described in the Sprint 6
// Task 9 spec (committed OCI layouts for Grafana / Airflow /
// Nginx / Postgres, ground-truth JSON files, ~52 metric gates
// against the pinned digests) is deferred to a Sprint 7
// follow-up — see `fixtures/README.md` for the handoff rationale.
// The synthetic in-process gates here pin each Sprint 6 Phase A
// + Phase B task's operator-facing contract end-to-end through
// the actual `astinus enrich` binary.
//
// S6 Task 9 (multi-image-acceptance-suite, ADR-0066).
package helpers
