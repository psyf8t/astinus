package model

// ComponentType is the canonical kind of a component.
//
// Values mirror CycloneDX componentType strings so that the most common
// case (CDX in, CDX out) is a no-op string copy. SPDX and other inputs
// map onto the same enum; entries we cannot classify become
// ComponentTypeUnknown rather than a silent default.
type ComponentType string

// Canonical component types. Add here when a real input requires it —
// don't add speculative entries.
const (
	ComponentTypeApplication ComponentType = "application"
	ComponentTypeContainer   ComponentType = "container"
	ComponentTypeDevice      ComponentType = "device"
	ComponentTypeFile        ComponentType = "file"
	ComponentTypeFirmware    ComponentType = "firmware"
	ComponentTypeFramework   ComponentType = "framework"
	ComponentTypeLibrary     ComponentType = "library"
	ComponentTypeOS          ComponentType = "operating-system"
	ComponentTypePlatform    ComponentType = "platform"
	ComponentTypeUnknown     ComponentType = "unknown"
)

// Component is one entry in the SBOM's component inventory.
//
// Fields fall into three groups:
//
//   - Format-portable (BOMRef, Name, Version, PURL, …) — present in
//     both CycloneDX and SPDX in some form.
//   - Astinus-added (LayerInfo, Origin) — populated by our enrichers.
//     These are also serialized into output as `astinus:*` Properties so
//     downstream consumers without our model can still read them.
//   - Structured-but-flat (Hashes, Licenses, Properties) — we keep the
//     structure but flatten OrganizationalEntity / LicenseChoice into
//     simple values; the spec calls this out as acceptable for the MVP.
type Component struct {
	// BOMRef is the unique identifier of this component within the
	// SBOM. Required to be populated by the reader; if the source
	// SBOM did not have one, the reader synthesizes one (see
	// cyclonedx mapper).
	BOMRef string

	// Type categorises the component. Defaults to
	// ComponentTypeUnknown when the source omits or uses an
	// unsupported value.
	Type ComponentType

	// Group is the namespace of the component (e.g. Maven groupId,
	// npm scope). Empty for ungrouped components.
	Group string

	// Name is the primary identifier. Always populated — readers
	// reject components without a name.
	Name string

	// Version is the component version string verbatim.
	Version string

	// Description is a free-form, human-readable description.
	Description string

	// Scope captures CycloneDX `scope` (required, optional, excluded).
	Scope string

	// PURL is the Package URL (https://github.com/package-url/purl-spec).
	PURL string

	// CPEs is the list of Common Platform Enumeration identifiers.
	// CycloneDX 1.6 only allows one `cpe` per component; we accept
	// many for our own enricher output and the writer concatenates /
	// duplicates as needed.
	CPEs []string

	// Hashes is the list of cryptographic digests for this component
	// or its primary artifact.
	Hashes []Hash

	// Licenses is the resolved license set. Either an SPDX expression
	// or a raw name; see License.
	Licenses []License

	// Supplier is the flattened supplier name. We deliberately do not
	// model OrganizationalEntity in MVP.
	Supplier string

	// Author / Publisher / Copyright are free-form attribution fields.
	Author    string
	Publisher string
	Copyright string

	// Properties is the bag of free-form key/value data. Custom
	// Astinus fields use the `astinus:*` namespace (see properties.go).
	Properties map[string]string

	// Evidence is provenance information about how this component was
	// identified — see Evidence.
	Evidence *Evidence

	// SubComponents are nested components (e.g. a container component
	// containing layer file components). Nesting depth is preserved
	// from the source SBOM.
	SubComponents []Component

	// LayerInfo is set by the layer-attribution enricher. Nil when
	// not yet enriched. Also serialized as `astinus:layer:*` Properties.
	LayerInfo *LayerInfo

	// Origin is set by the base-image-diff enricher. Empty string is
	// equivalent to OriginUnknown.
	Origin Origin
}

// LayerInfo is the layer-level provenance of a Component, populated by
// the attribution enricher.
type LayerInfo struct {
	LayerDigest    string
	LayerIndex     int
	DockerfileLine string
	AddedBy        string
}

// Origin classifies a Component as belonging to the base image, the
// application layer on top, or being unattributable.
type Origin string

// Canonical Origin values.
const (
	OriginBaseImage   Origin = "base"
	OriginApplication Origin = "app"
	OriginUnknown     Origin = "unknown"
)

// IsKnown reports whether o is one of the recognised non-empty values.
func (o Origin) IsKnown() bool {
	switch o {
	case OriginBaseImage, OriginApplication, OriginUnknown:
		return true
	default:
		return false
	}
}
