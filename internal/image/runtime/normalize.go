package runtime

import (
	"fmt"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// InstructionType is the Dockerfile-level instruction we attribute to
// a layer. The set is intentionally small — squashed layers and ones
// without a recoverable instruction get InstructionUnknown rather
// than a guess.
type InstructionType string

// Instruction kinds Astinus distinguishes.
const (
	InstructionFROM    InstructionType = "FROM"
	InstructionRUN     InstructionType = "RUN"
	InstructionCOPY    InstructionType = "COPY"
	InstructionADD     InstructionType = "ADD"
	InstructionENV     InstructionType = "ENV"
	InstructionLABEL   InstructionType = "LABEL"
	InstructionARG     InstructionType = "ARG"
	InstructionUNKNOWN InstructionType = "UNKNOWN"
)

// NormalizedLayer is one tar layer with its Dockerfile-level history
// entry resolved (if available) and runtime-specific quirks stripped
// from CreatedBy. The structure is the contract Task 2 (basediff) and
// later sprint work depend on; treat its public field set as stable.
type NormalizedLayer struct {
	// Index is the 0-based layer index within the image (bottom is 0).
	Index int

	// Digest is the layer's compressed digest as it appears in the
	// manifest ("sha256:..."). Empty when the source could not surface
	// the digest (extremely rare; logged but not fatal).
	Digest string

	// DiffID is the sha256 of the uncompressed tar bytes — the
	// rootfs.diff_ids value from the image config.
	DiffID string

	// Size is the compressed layer size in bytes.
	Size int64

	// CreatedBy is the Dockerfile instruction that produced the
	// layer, with the runtime-specific prefix (e.g.
	// "containers-storage:") stripped. Empty when no history entry
	// could be paired with this layer.
	CreatedBy string

	// Created is the layer's creation timestamp from the history
	// entry. Zero when no history entry could be paired.
	Created time.Time

	// Comment is the optional history comment.
	Comment string

	// EmptyLayer mirrors the matching history entry's flag. Always
	// false here: NormalizedLayer is only emitted for layers with a
	// real tar payload. Kept for symmetry with v1.History.
	EmptyLayer bool

	// InstructionType is the parsed Dockerfile instruction kind. Set
	// to InstructionUNKNOWN when CreatedBy could not be classified.
	InstructionType InstructionType

	// RuntimeMetadata is a free-form bag of runtime-specific notes
	// (e.g. "squashed=likely" for Kaniko). Always non-nil after
	// Normalize so callers can write into it without a nil check.
	RuntimeMetadata map[string]string
}

// Normalize turns img's layer list and history into a flat slice of
// NormalizedLayer entries with runtime-specific quirks applied.
//
// History/layer alignment is the load-bearing logic: OCI history
// entries with EmptyLayer=true contribute no tar layer (e.g. ENV,
// LABEL, ARG), so the alignment must skip them. When history is
// shorter than the layer list (typical for squashed images, partial
// pulls, or images built by tools that omit history) the trailing
// layers get empty CreatedBy / InstructionUnknown rather than a
// guess.
func Normalize(rt Runtime, img v1.Image) ([]NormalizedLayer, error) {
	if img == nil {
		return nil, fmt.Errorf("runtime: nil image")
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("runtime: read config: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("runtime: read layers: %w", err)
	}

	out := make([]NormalizedLayer, 0, len(layers))
	historyIdx := 0
	for i, layer := range layers {
		nl := NormalizedLayer{
			Index:           i,
			InstructionType: InstructionUNKNOWN,
			RuntimeMetadata: map[string]string{},
		}

		if d, err := layer.Digest(); err == nil {
			nl.Digest = d.String()
		}
		if d, err := layer.DiffID(); err == nil {
			nl.DiffID = d.String()
		}
		if s, err := layer.Size(); err == nil {
			nl.Size = s
		}

		// Advance through history entries, skipping empty-layer
		// entries until we find the next non-empty one (which is the
		// history record paired with this real layer).
		for historyIdx < len(cf.History) {
			h := cf.History[historyIdx]
			historyIdx++
			if h.EmptyLayer {
				continue
			}
			nl.CreatedBy = h.CreatedBy
			nl.Created = h.Created.Time
			nl.Comment = h.Comment
			nl.InstructionType = parseInstructionType(h.CreatedBy)
			break
		}

		applyRuntimeQuirks(rt, &nl)
		// Re-parse instruction type after quirks may have stripped a
		// prefix that confused the parser (e.g. "containers-storage:").
		if nl.InstructionType == InstructionUNKNOWN && nl.CreatedBy != "" {
			nl.InstructionType = parseInstructionType(nl.CreatedBy)
		}
		out = append(out, nl)
	}
	return out, nil
}

// parseInstructionType extracts the Dockerfile instruction kind from
// a history.CreatedBy string.
//
// Three shapes appear in the wild:
//
//  1. Legacy Docker `#(nop)` form:
//     "/bin/sh -c #(nop) COPY file:abc... in /app/"
//  2. Buildah / newer Docker direct form:
//     "COPY file:abc... in /app/"
//  3. RUN form:
//     "/bin/sh -c apt-get update" or "RUN /bin/sh -c ..."
//
// Anything we cannot classify becomes InstructionUNKNOWN — guessing
// hurts more than it helps because downstream code uses the kind to
// drive heuristics.
func parseInstructionType(createdBy string) InstructionType {
	s := strings.TrimSpace(createdBy)
	if s == "" {
		return InstructionUNKNOWN
	}

	// Shape 1: legacy "/bin/sh -c #(nop) <INSTR> ..."
	if i := strings.Index(s, "#(nop)"); i >= 0 {
		rest := strings.TrimSpace(s[i+len("#(nop)"):])
		return classifyInstructionWord(rest)
	}

	// Shape 3-explicit: "RUN /bin/sh -c ..."
	if hasInstructionPrefix(s, "RUN ") {
		return InstructionRUN
	}

	// Shape 2: bare instruction at the start.
	if it := classifyInstructionWord(s); it != InstructionUNKNOWN {
		return it
	}

	// Shape 3-implicit: any "/bin/sh -c ..." without a #(nop) marker
	// is a RUN. Buildah also emits "/bin/sh -c <cmd>" without the
	// nop marker for real RUN instructions.
	if strings.HasPrefix(s, "/bin/sh -c") || strings.HasPrefix(s, "/bin/bash -c") {
		return InstructionRUN
	}

	return InstructionUNKNOWN
}

// classifyInstructionWord checks whether s starts with a recognised
// Dockerfile instruction keyword (case-insensitive, followed by a
// space or tab).
func classifyInstructionWord(s string) InstructionType {
	upper := strings.ToUpper(s)
	for _, it := range []InstructionType{
		InstructionFROM, InstructionRUN, InstructionCOPY, InstructionADD,
		InstructionENV, InstructionLABEL, InstructionARG,
	} {
		prefix := string(it) + " "
		if strings.HasPrefix(upper, prefix) {
			return it
		}
	}
	return InstructionUNKNOWN
}

// hasInstructionPrefix is a case-insensitive HasPrefix that requires
// the prefix to be a whole word (avoids matching "RUNTIME" as "RUN").
func hasInstructionPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// applyRuntimeQuirks rewrites NormalizedLayer fields to compensate for
// per-runtime CreatedBy formatting choices. Called once per layer
// after history alignment.
func applyRuntimeQuirks(rt Runtime, nl *NormalizedLayer) {
	switch rt {
	case RuntimeKaniko:
		// Kaniko collapses many instructions into a single layer.
		// The signal here lets downstream attribution mark the layer
		// as low-confidence.
		nl.RuntimeMetadata["squashed"] = "likely"

	case RuntimePodman, RuntimeBuildah:
		nl.CreatedBy = strings.TrimSpace(strings.TrimPrefix(nl.CreatedBy, "containers-storage:"))
		// Buildah occasionally emits "/bin/sh -c <cmd>" with a
		// leading "buildah" prefix for nop-style commands.
		nl.CreatedBy = strings.TrimSpace(strings.TrimPrefix(nl.CreatedBy, "buildah:"))

	case RuntimeBuildKit:
		// BuildKit's frontend may prefix entries with the frontend
		// identifier — strip so the parsed instruction is the
		// Dockerfile instruction, not the frontend marker.
		nl.CreatedBy = strings.TrimSpace(strings.TrimPrefix(nl.CreatedBy, "buildkit:"))
		nl.CreatedBy = strings.TrimSpace(strings.TrimPrefix(nl.CreatedBy, "buildkit.dockerfile.v0:"))

	case RuntimeJib, RuntimeKo, RuntimeDocker, RuntimeUnknown:
		// no-op
	}
}
