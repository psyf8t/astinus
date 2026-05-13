//go:build acceptance

// Package helpers carries the Sprint 5 Phase A acceptance suite's
// minimal infrastructure. Most tests reuse Sprint 3 helpers (binary
// builder, RunEnrich subprocess wrapper) and Sprint 4 helpers
// (OCIImageWithFiles, WriteCDXSBOM, FindComponent, PropertyValue,
// MetadataProperty); this package adds only what the Sprint 5
// gates specifically need on top.
//
// Build tag: every file in this tree carries `//go:build acceptance`
// so the default `go test ./...` invocation skips them. CI invokes
// the suite explicitly:
//
//	go test -tags acceptance -v -timeout 5m ./test/acceptance/sprint5/...
//
// The full pinned-Grafana real-image bundle described in the Sprint
// 5 Task 5 spec (committed OCI layout, ground-truth JSON for 611
// components, Grype delta gates) is deferred to a follow-up — see
// `fixtures/README.md`. The synthetic in-process gates in this
// directory pin each Phase A task's operator-facing contract end-
// to-end through the binary.
//
// S5 Task 5 (sprint5-acceptance-suite, ADR-0052).
package helpers
