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

	// Provenance about how Astinus identified the component.
	PropertyEvidenceMethod     = "astinus:evidence:method"
	PropertyEvidenceConfidence = "astinus:evidence:confidence"

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
