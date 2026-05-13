// Package vex reads Vulnerability Exploitability eXchange documents
// — OpenVEX (https://github.com/openvex/spec) and the CycloneDX VEX
// flavour — and exposes a unified lookup the compliance gate
// consults to suppress vulnerabilities the operator has explicitly
// marked `not_affected` or `fixed`.
//
// Two formats are recognised by content (no extension matching —
// operators routinely save VEX as `.json` either way):
//
//   - OpenVEX: top-level `@context` field starting with
//     `https://openvex.dev/ns/`.
//   - CycloneDX VEX: top-level `bomFormat == "CycloneDX"` AND a
//     `vulnerabilities[]` array. (A normal CDX SBOM with both
//     `components[]` and `vulnerabilities[]` is fine too — we read
//     only the vulnerabilities side.)
//
// Statements with `status == "not_affected"` or `status == "fixed"`
// produce `Effect` rows in the unified store; `Lookup` returns the
// effect for a (vulnID, productPURL) pair when one of:
//
//   - PURL equals the effect's product PURL exactly, or
//   - PURL's base (stripped @version) equals the effect's base AND
//     either side carries `@*` (operator-asserted "any version").
//
// Future extensions (deferred per ADR-0063): version-range matching,
// CSAF VEX format, signed VEX via Cosign attestation. S6 Task 6 /
// ADR-0063.
package vex
