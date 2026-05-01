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
)
