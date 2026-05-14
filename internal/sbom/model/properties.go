package model

// Property name constants for the Astinus-controlled namespace.
//
// Every property Astinus emits into a foreign-format SBOM
// (CycloneDX/SPDX) uses one of the names below so consumers can
// recognise our additions and so we never collide with another tool's
// custom keys.
//
// The structural fields on Component (LayerInfo, Origin, …) are the
// authoritative storage — these constants exist for the writers that
// project the canonical model into a format and for documentation.
const (
	// PropertyNamespace is the prefix every Astinus-emitted property
	// shares.
	PropertyNamespace = "astinus"

	// Origin (Component.Origin) — value is one of OriginBaseImage,
	// OriginApplication, OriginUnknown.
	PropertyOrigin = "astinus:origin"

	// Layer attribution (Component.LayerInfo).
	PropertyLayerDigest         = "astinus:layer:digest"
	PropertyLayerIndex          = "astinus:layer:index"
	PropertyLayerDockerfileLine = "astinus:layer:dockerfile-line"
	PropertyLayerAddedBy        = "astinus:layer:added-by"
	// PropertyLayerCompressedDigest carries the registry-blob hash
	// (`manifest.layers[i].digest`) supplementing the canonical
	// rootfs.diff_id in PropertyLayerDigest. S5 Task 2.
	PropertyLayerCompressedDigest = "astinus:layer:compressed-digest"
	// PropertyLayerSource records which discovery path produced the
	// layer attribution: a filesystem-walk last-touch lookup
	// ("filemap-last-touch") or a translated Syft location
	// ("syft-location-property"). S4 Task 2.
	PropertyLayerSource = "astinus:layer:source"

	// Provenance about how Astinus identified the component.
	PropertyEvidenceMethod     = "astinus:evidence:method"
	PropertyEvidenceConfidence = "astinus:evidence:confidence"

	// EvidenceLevel — "identified" (verifiable metadata: buildinfo,
	// manifest, package record, content-hash match) vs "observed"
	// (we saw the file, recorded its path/hash/layer, but cannot
	// make a package-identity claim). S4 Task 0.
	PropertyEvidenceLevel = "astinus:evidence-level"

	// CPE-mode metadata stamped onto sbom.Metadata.Properties so
	// downstream consumers can tell apart full-online enrichment
	// from a degraded-auto run. S4 Task 4 / S5 Task 4.
	PropertyCPEMode = "astinus:cpe:mode"
	// PropertyCPESourcesUsed is a comma-separated list of CPE
	// sources that ran during enrichment. Companion to
	// PropertyCPESourcesSkipped. S5 Task 4.
	PropertyCPESourcesUsed = "astinus:cpe:sources-used"
	// PropertyCPESourcesSkipped is a comma-separated list of CPE
	// sources skipped (each entry is `<source>:<reason>` per the
	// S5 Task 4 finalised format). Empty when every recognised
	// source ran.
	PropertyCPESourcesSkipped = "astinus:cpe:sources-skipped"
	// PropertyCPETotalCapHit is "true" when the CPE enricher's
	// total wall-time cap (`--cpe-total-timeout`, default 3 m)
	// fired and the run emitted a partial-enriched SBOM. Absent
	// or "false" when the enricher completed inside the budget.
	// S6 Task 0 / ADR-0057.
	PropertyCPETotalCapHit = "astinus:cpe:total-cap-hit"
	// PropertyCPEElapsedSeconds is the wall-time the CPE enricher
	// spent on this run, rendered as a 2-decimal seconds value.
	// Operator diagnostic — pairs with PropertyCPETotalCapHit.
	// S6 Task 0.
	PropertyCPEElapsedSeconds = "astinus:cpe:elapsed-seconds"
	// PropertyCPEComponentsProcessed records how many components
	// the enricher walked before exiting. Equals the SBOM's
	// component count on a clean finish; less than it when the
	// total cap fired. S6 Task 0.
	PropertyCPEComponentsProcessed = "astinus:cpe:components-processed"
	// PropertyCPESourceStatusPrefix is the per-source completion-
	// status property family: `astinus:cpe:source-status:<name>`
	// carries one of `complete`, `budget-exhausted:<duration>`,
	// `timeout`, `errored`, or the same `<source>:<reason>`
	// vocabulary the sources-skipped list uses. Lets operators
	// see per-source outcome without parsing the aggregate lists.
	// S6 Task 0 / ADR-0057.
	PropertyCPESourceStatusPrefix = "astinus:cpe:source-status:"
	// PropertyCPETotalCapConfigured / PropertyCPESourceTimeoutConfigured
	// / PropertyCPECallTimeoutConfigured stamp the operator-supplied
	// wall-time bounds at run start. When :total-cap-hit fires,
	// operators read the SBOM and see both the elapsed wall-time AND
	// the cap that produced the trip — no need to cross-reference the
	// CLI invocation. S8 Task 0 / ADR-0057 amendment.
	PropertyCPETotalCapConfigured      = "astinus:cpe:total-cap-configured"
	PropertyCPESourceTimeoutConfigured = "astinus:cpe:source-timeout-configured"
	PropertyCPECallTimeoutConfigured   = "astinus:cpe:call-timeout-configured"
	// PropertyCPEInputNormalisedCount counts the input CPEs the
	// URL-percent → backslash-escape normaliser repaired during a
	// single Enrich call (NIST IR 7695 §6.1.2.5). Always present on
	// a completed run — `0` means no repair was needed, absent means
	// the enricher never ran. S8 Task 1 / ADR-0058 amendment.
	PropertyCPEInputNormalisedCount = "astinus:cpe:input-normalised-count"

	// Top-level metadata stamp emitted on every Astinus-touched SBOM.
	PropertyEnrichedBy      = "astinus:enriched-by"
	PropertyEnrichedVersion = "astinus:enriched-version"

	// Build-runtime detection (PRSD Task 0). Stamped on
	// Metadata.Properties so the result is a single observation per
	// SBOM, not duplicated per component.
	PropertyRuntime         = "astinus:runtime"
	PropertyRuntimeEvidence = "astinus:runtime:evidence"

	// Attribution confidence (PRSD Task 0). Reflects how much we
	// trust LayerInfo across the SBOM — squashed images from Kaniko
	// get "low", BuildKit-with-provenance gets "high", normal Docker
	// builds get "medium".
	PropertyAttributionConfidence = "astinus:attribution:confidence"
	PropertyAttributionReason     = "astinus:attribution:reason"

	// Base-image diff strategy + per-component forensic evidence
	// (PRSD Task 2). Strategy stamps the SBOM-level Metadata; the
	// other three live on the matched Component.
	PropertyBasediffStrategy        = "astinus:basediff:strategy"
	PropertyBasediffMatchedBasePath = "astinus:basediff:matched-base-path"
	PropertyBasediffState           = "astinus:basediff:state"
	PropertyBasediffConfidence      = "astinus:basediff:confidence"

	// Compliance findings (PRSD Task 7). Stamped on Metadata.Properties
	// after every validator runs. Per-validator status carries the
	// pass/warn/fail summary; aggregate counts surface at SBOM level.
	// Per-component findings are stamped on the matched Component as
	// `astinus:compliance:finding:<rule-id>=<severity>`.
	PropertyComplianceFindingsCount = "astinus:compliance:findings-count"
	PropertyComplianceCriticalCount = "astinus:compliance:critical-count"
	PropertyComplianceHighCount     = "astinus:compliance:high-count"
	PropertyComplianceMediumCount   = "astinus:compliance:medium-count"
	PropertyComplianceLowCount      = "astinus:compliance:low-count"
	// PropertyComplianceInfoCount is the count of SeverityInfo
	// findings (added in S3 Task 2 — informational findings emitted
	// by the per-ecosystem severity policy).
	PropertyComplianceInfoCount = "astinus:compliance:info-count"
	// PropertyComplianceActionableCount is the sum of
	// critical + high + medium findings — the value security teams
	// should look at first. S3 Task 2.
	PropertyComplianceActionableCount = "astinus:compliance:actionable-findings-count"
)
