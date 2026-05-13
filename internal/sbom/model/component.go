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
//
// S5 Task 2 split the single layer-digest field into the OCI
// image-spec's canonical pair: LayerDigest carries the rootfs
// `diff_id` (sha256 of the uncompressed tar — stable across
// compression scheme changes and across docker save / crane pull /
// skopeo copy), and LayerCompressedDigest carries the registry
// blob hash (`manifest.layers[].digest`) when available. Pre-S5
// LayerDigest carried the compressed digest under a misleading
// name; run #3 benchmark caught the resulting 0/20 sample-accuracy
// against ground-truth diff_ids.
type LayerInfo struct {
	// LayerDigest is the OCI rootfs diff_id (uncompressed tar
	// sha256). The canonical OCI layer identifier; SBOM consumers
	// map this 1:1 against the image config's `rootfs.diff_ids`
	// array.
	LayerDigest string
	// LayerCompressedDigest is the registry-blob hash from the
	// manifest (`manifest.layers[i].digest`). Empty when the
	// backend can't produce it (some OCI-layout / daemon paths)
	// or when the layer descriptor lookup failed. S5 Task 2.
	LayerCompressedDigest string
	LayerIndex            int
	DockerfileLine        string
	AddedBy               string
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

// EvidenceLevel records how strong our identity claim is for a
// Component. Set by enrichers that emit Components from observation
// (untracked file walk, base-image diff) so downstream consumers can
// tell apart "this is package X" from "we saw this file, we don't
// know what it is". Serialised as `astinus:evidence-level` property.
//
// S4 Task 0 introduced this distinction after a real-image audit
// found Astinus emitting phantom `pkg:generic/<basename>` components
// for stripped non-Go binaries (busybox symlinks, openssl helpers).
// Those entries scored as `identified` in earlier versions and so
// triggered Grype CVE matches that had no factual basis.
type EvidenceLevel string

// Canonical EvidenceLevel values.
const (
	// EvidenceLevelIdentified means the Component carries a
	// verifiable identity: a package manager record, embedded
	// buildinfo (Go / Rust auditable), a signed JAR manifest, or
	// a Software Heritage content-hash match.
	EvidenceLevelIdentified EvidenceLevel = "identified"

	// EvidenceLevelObserved means we recorded the file (path,
	// SHA-256, layer) without making a verifiable claim about its
	// package identity. Such Components carry empty PURL and CPE.
	EvidenceLevelObserved EvidenceLevel = "observed"
)
