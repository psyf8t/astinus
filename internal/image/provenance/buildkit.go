package provenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ErrNoProvenance is returned when the supplied image / index does
// not carry a recoverable in-toto SLSA provenance attestation. It is
// the caller's signal to fall back to other evidence (history,
// labels) without treating the absence as an error condition.
var ErrNoProvenance = errors.New("provenance: no attestation found")

// Annotation keys BuildKit uses to mark attestation manifests in an
// OCI Image Index.
const (
	annotationReferenceType   = "vnd.docker.reference.type"
	annotationReferenceDigest = "vnd.docker.reference.digest"
	referenceTypeAttestation  = "attestation-manifest"

	// slsaPredicateTypeV02 is the predicate type for SLSA Provenance
	// v0.2 statements (the version BuildKit emits as of 2024).
	slsaPredicateTypeV02 = "https://slsa.dev/provenance/v0.2"
	// slsaPredicateTypeV1 is the v1 predicate type, accepted for
	// forward compatibility.
	slsaPredicateTypeV1 = "https://slsa.dev/provenance/v1"
)

// BuildKitProvenance is the parsed SLSA Provenance predicate plus the
// in-toto envelope fields we need for attribution. We deliberately do
// not surface every nested field — callers want the materials
// (sources), the build steps, and the builder identity.
type BuildKitProvenance struct {
	// PredicateType is the in-toto predicate type URL
	// (e.g. "https://slsa.dev/provenance/v0.2").
	PredicateType string

	// BuildType is the SLSA buildType URL identifying the build
	// recipe shape (BuildKit emits its own URL).
	BuildType string

	// Builder identifies the build tool.
	Builder BuilderInfo

	// Materials are the inputs to the build (Dockerfile source,
	// base images, fetched URLs) with their digests.
	Materials []Material

	// BuildSteps are the per-step records BuildKit emits in
	// metadata.buildkit.frontends or in the SLSA invocation
	// parameters. Empty when the source did not include them.
	BuildSteps []BuildStep

	// StartedOn / FinishedOn are the build timestamps from the SLSA
	// metadata block. Zero when not present.
	StartedOn  time.Time
	FinishedOn time.Time
}

// BuilderInfo identifies the build tool that produced the attestation.
type BuilderInfo struct {
	// ID is the builder identity URL (e.g.
	// "https://github.com/docker/buildkit@v0.13.0").
	ID string
	// Version is the parsed version segment when the ID is suffixed.
	Version string
}

// Material is one input to the build, with its content-addressed
// digest set.
type Material struct {
	// URI is the source location (e.g. "git+https://github.com/...",
	// "pkg:docker/library/alpine@sha256:...").
	URI string
	// Digest is the algorithm → hex digest map (typically
	// {"sha256": "..."} or {"sha1": "..."} for git).
	Digest map[string]string
}

// BuildStep is one Dockerfile-instruction-level entry from the SLSA
// invocation. Optional in BuildKit's emission — present in
// `--attest=mode=max` builds, omitted in `mode=min`.
type BuildStep struct {
	Index   int
	Command string
	// AddedFiles is empty for now — BuildKit does not emit per-step
	// file lists in the standard SLSA shape. Reserved for future
	// extraction from the .buildkit metadata block.
	AddedFiles []string
}

// inTotoStatement is the on-the-wire shape of the in-toto envelope
// BuildKit writes as the attestation manifest's config blob.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []subjectEntry  `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type subjectEntry struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// slsaProvenanceV02 is the subset of the SLSA v0.2 predicate we read.
type slsaProvenanceV02 struct {
	Builder struct {
		ID string `json:"id"`
	} `json:"builder"`
	BuildType  string `json:"buildType"`
	Invocation struct {
		ConfigSource struct {
			URI string `json:"uri"`
		} `json:"configSource"`
		Parameters json.RawMessage `json:"parameters,omitempty"`
	} `json:"invocation"`
	Metadata struct {
		BuildStartedOn  time.Time `json:"buildStartedOn,omitempty"`
		BuildFinishedOn time.Time `json:"buildFinishedOn,omitempty"`
	} `json:"metadata"`
	Materials []slsaMaterial `json:"materials"`
}

type slsaMaterial struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// FindAttestation walks an OCI Image Index and returns the attestation
// manifest that targets the supplied platform image digest.
//
// Returns ErrNoProvenance when no entry carries
// `vnd.docker.reference.type=attestation-manifest` plus a matching
// `vnd.docker.reference.digest`. Callers should treat that as a
// "no provenance available" signal, not a hard failure.
func FindAttestation(idx v1.ImageIndex, targetDigest v1.Hash) (v1.Image, error) {
	if idx == nil {
		return nil, ErrNoProvenance
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("provenance: read index manifest: %w", err)
	}
	target := targetDigest.String()
	for _, desc := range manifest.Manifests {
		if desc.Annotations[annotationReferenceType] != referenceTypeAttestation {
			continue
		}
		if desc.Annotations[annotationReferenceDigest] != target {
			continue
		}
		img, err := idx.Image(desc.Digest)
		if err != nil {
			return nil, fmt.Errorf("provenance: load attestation manifest: %w", err)
		}
		return img, nil
	}
	return nil, ErrNoProvenance
}

// Extract parses the in-toto SLSA Provenance statement carried by the
// attestation manifest's config blob.
//
// Returns ErrNoProvenance when img is not an attestation manifest
// (its config blob is not a recognisable in-toto statement). That is
// the expected outcome for plain platform images.
//
// When img IS an attestation manifest but its predicate type is not
// SLSA v0.2 / v1, Extract returns a BuildKitProvenance with
// PredicateType set and the rest of the fields empty — the caller
// can decide whether to attempt format-specific parsing.
func Extract(img v1.Image) (*BuildKitProvenance, error) {
	if img == nil {
		return nil, ErrNoProvenance
	}
	rawConfig, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("provenance: read attestation config: %w", err)
	}
	var stmt inTotoStatement
	if err := json.Unmarshal(rawConfig, &stmt); err != nil {
		// The config blob is not JSON or not an in-toto statement —
		// this is the common case when img is a regular OCI image
		// rather than an attestation manifest.
		return nil, ErrNoProvenance
	}
	if stmt.Type == "" || stmt.PredicateType == "" {
		return nil, ErrNoProvenance
	}

	out := &BuildKitProvenance{PredicateType: stmt.PredicateType}

	switch stmt.PredicateType {
	case slsaPredicateTypeV02, slsaPredicateTypeV1:
		var p slsaProvenanceV02
		if err := json.Unmarshal(stmt.Predicate, &p); err != nil {
			return nil, fmt.Errorf("provenance: parse SLSA predicate: %w", err)
		}
		populateFromSLSA(out, &p)
	}

	return out, nil
}

// populateFromSLSA copies the subset of the SLSA predicate Astinus
// downstream consumers care about into the BuildKitProvenance.
func populateFromSLSA(out *BuildKitProvenance, p *slsaProvenanceV02) {
	out.BuildType = p.BuildType
	out.Builder.ID = p.Builder.ID
	out.Builder.Version = parseBuilderVersion(p.Builder.ID)
	out.StartedOn = p.Metadata.BuildStartedOn
	out.FinishedOn = p.Metadata.BuildFinishedOn

	out.Materials = make([]Material, 0, len(p.Materials))
	for _, m := range p.Materials {
		out.Materials = append(out.Materials, Material{
			URI:    m.URI,
			Digest: cloneStringMap(m.Digest),
		})
	}
}

// parseBuilderVersion extracts the trailing `@v…` segment from a
// builder ID URL like "https://github.com/docker/buildkit@v0.13.0".
// Returns the empty string when no version is present.
func parseBuilderVersion(id string) string {
	at := -1
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 || at == len(id)-1 {
		return ""
	}
	return id[at+1:]
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
