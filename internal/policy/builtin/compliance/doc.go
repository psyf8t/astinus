// Package compliance ships the bundled SBOM validators Astinus
// runs by default in production deployments:
//
//   - NTIAValidator        — US Executive Order 14028's "Minimum
//     Elements for an SBOM" (NTIA report 2021-07-12).
//   - EUCRAValidator       — EU Cyber Resilience Act Article 13 +
//     Annex I, the auditable subset.
//   - CycloneDXStructural  — CycloneDX 1.6 required-field shape
//     (no full JSONSchema dependency).
//   - SPDXStructural       — SPDX 2.3 required-field shape (same).
//
// # Why "structural" instead of full JSONSchema
//
// The CycloneDX 1.6 and SPDX 2.3 schemas are megabyte-sized JSON
// documents. Embedding them + pulling in `santhosh-tekuri/jsonschema`
// (the spec-suggested validator) would add one direct dep + several
// transitives for a check the validators here perform with `~50 LOC`
// of field-presence assertions. The structural validators catch the
// dominant missing-required-field shapes that cause downstream
// consumers to reject our SBOMs; the rare schema-but-not-structural
// failures are documented as future work in ADR-0025.
//
// Same precedent as PRSD-Task-1/2/3/4/5/6 (in-tree trie / bloom /
// TOML / extractor / token-bucket / topo-sort).
//
// # What these validators do NOT do
//
// They do not enforce policy beyond the cited regulation; they do
// not block the pipeline (the compliance enricher writes findings as
// SBOM properties; the CLI's `--fail-on` flag handles exit codes).
package compliance
