package model

// RelationshipType is the kind of edge between two components.
//
// Values are mostly aligned with SPDX Relationship types but mapped to
// the much smaller set CycloneDX expresses (which only distinguishes
// dependsOn / provides / contains via dependencies + nested components).
type RelationshipType string

// Canonical relationship types.
const (
	RelationshipDependsOn RelationshipType = "depends-on"
	RelationshipProvides  RelationshipType = "provides"
	RelationshipContains  RelationshipType = "contains"
	RelationshipUnknown   RelationshipType = "unknown"
)

// Relationship is a directed edge SourceRef -> TargetRef.
//
// Both refs MUST resolve to a Component.BOMRef somewhere in the SBOM
// (top-level or nested). Validators may flag dangling refs.
type Relationship struct {
	SourceRef string
	TargetRef string
	Type      RelationshipType
}
