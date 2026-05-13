//go:build acceptance

// Package helpers carries the Sprint 4 acceptance suite's shared
// infrastructure — astinus binary builder, fixture loaders, output
// readers. Sprint 4 mostly reuses the Sprint 3 helpers package; the
// few additions live here so the suite owns the surface it depends
// on without forcing changes back into Sprint 3.
//
// Build tag: every file in this tree carries `//go:build acceptance`
// so the default `go test ./...` invocation skips them. CI invokes
// the suite explicitly:
//
//	go test -tags acceptance -v -timeout 5m ./test/acceptance/sprint4/...
//
// S4 Task 7 (sprint4-acceptance-suite).
package helpers
