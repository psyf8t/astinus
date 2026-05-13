// Package model is the canonical, format-agnostic SBOM representation.
//
// Every reader (CycloneDX, SPDX, …) parses into model.SBOM. Every
// enricher operates on it. Every writer serializes from it. The model
// intentionally has no dependency on cyclonedx-go, spdx-tools, or any
// other format library — keeping it independent is the precondition
// for round-trip safety and for testing enrichers in isolation.
//
// # Round-trip strategy
//
// When a reader populates SBOM it also stashes the input body in
// SourceRaw and records the originating Format in SourceFormat. The
// writer for a matching format MAY consult SourceRaw to preserve fields
// the canonical model does not yet model (CycloneDX 1.6 is large; we
// model the well-trodden subset and let exotic fields ride along
// unchanged). For now, however, the CycloneDX writer always renders
// from the canonical model and SourceRaw exists for the next stage's
// fall-back logic.
//
// Astinus-added information (LayerInfo, Origin, evidence collected by
// our own enrichers) lives on the canonical Component as typed fields
// AND is serialized into the output as `astinus:*` properties so that
// downstream consumers that don't understand the canonical model can
// still read everything we added.
package model

import (
	"strings"
	"time"
)

// SBOM is a single Software Bill of Materials.
type SBOM struct {
	// Metadata is the top-level information about the SBOM itself
	// (when it was generated, by whom, the primary component it
	// describes).
	Metadata Metadata

	// Components is the flat list of components extracted from the
	// SBOM. Nested sub-components live under Component.SubComponents
	// — they are not duplicated here.
	Components []Component

	// Relationships captures dependency / containment edges between
	// components by BOMRef.
	Relationships []Relationship

	// Properties is the set of top-level key/value properties.
	// Astinus-emitted entries follow the `astinus:*` namespace
	// (see properties.go).
	Properties map[string]string

	// SourceFormat records which reader produced this SBOM.
	SourceFormat Format

	// SourceRaw is the raw byte body the reader consumed, kept so
	// future writers can preserve unmapped fields.
	SourceRaw []byte
}

// Metadata mirrors the bomMetadata of CycloneDX and the document-level
// fields of SPDX.
type Metadata struct {
	// Timestamp is when the SBOM was generated. Zero value means unknown.
	Timestamp time.Time
	// Authors lists humans who authored the SBOM.
	Authors []string
	// Tools lists software that produced the SBOM (e.g. Syft, cdxgen).
	Tools []Tool
	// Component is the primary subject of the SBOM (often the container
	// image being analyzed). Nil when not declared.
	Component *Component
	// Properties is metadata-level free-form key/value data.
	Properties map[string]string
}

// Tool identifies an SBOM-producing tool.
type Tool struct {
	Vendor  string
	Name    string
	Version string
}

// Source identifies the upstream tool that produced an SBOM.
// Astinus enrichers occasionally branch on the source — Trivy's
// CDX schema omits the `file`-type Components that Syft's
// catalogers emit, so the untracked walk sees binaries Trivy
// didn't enumerate and decisions like skip-set construction have
// to compensate. S4 Task 5.
type Source string

// Recognised SBOM sources. Returned by `DetectSource`. Unknown
// upstream tools (or SBOMs with no Tool entries) map to
// SourceOther.
const (
	SourceUnknown Source = ""
	SourceSyft    Source = "syft"
	SourceTrivy   Source = "trivy"
	SourceOther   Source = "other"
)

// DetectSource looks at sbom.Metadata.Tools to identify the
// upstream SBOM-producing tool. Returns the first match (Syft and
// Trivy are checked by case-insensitive substring, since both
// tools ship under slightly different vendor / name combinations
// across versions and CI distributions).
func DetectSource(sbom *SBOM) Source {
	if sbom == nil {
		return SourceUnknown
	}
	for _, tool := range sbom.Metadata.Tools {
		name := strings.ToLower(tool.Name)
		vendor := strings.ToLower(tool.Vendor)
		switch {
		case strings.Contains(name, "syft"),
			strings.Contains(vendor, "anchore"):
			return SourceSyft
		case strings.Contains(name, "trivy"),
			strings.Contains(vendor, "aquasecurity"),
			strings.Contains(vendor, "aqua security"):
			return SourceTrivy
		}
	}
	if len(sbom.Metadata.Tools) == 0 {
		return SourceUnknown
	}
	return SourceOther
}
