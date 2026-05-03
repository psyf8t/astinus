// Package benchmarks contains the perf gates Astinus must pass
// before a v0.2.0 release (PRSD-Task-9):
//
//   - 1 GiB image enriched in < 2 minutes wall-clock,
//   - 5 GiB image enriched in < 8 minutes wall-clock,
//   - 5 GiB image memory peak < 4 GiB.
//
// Built only under `//go:build benchmark` so default `go test ./...`
// is unaffected. The 1 GiB / 5 GiB images are synthesised in a
// temp dir (random-bytes payload + a real package layer so the
// extractors actually have something to match on).
//
// To run:
//
//	go test -tags benchmark -bench=. ./test/benchmarks/...
//
// On CI the workflow `acceptance.yml` invokes the same target.
package benchmarks
