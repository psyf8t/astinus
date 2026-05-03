// Package scanners holds the vulnerability-scanner integration
// tests for PRSD-Task-9. Each test asserts that a third-party
// scanner (Grype, OSV-Scanner, Trivy) finds CVE-2021-44228
// (Log4Shell) in the same shared log4j-2.14.1 image, given
// Astinus's enriched SBOM as input.
//
// The shared dockerfile + CVE id live in `log4shell_dockerfile.go`
// (no build tag) so the constants are reachable from the per-
// scanner `*_test.go` files (each gated with
// `//go:build acceptance`).
package scanners
