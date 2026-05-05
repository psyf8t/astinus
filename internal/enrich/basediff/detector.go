// Package basediff splits the SBOM's components into "from the base
// image" vs "from the application layer on top" so an operator can
// see exactly which components their team is responsible for.
//
// The strategy (per spec section 8.7) is:
//
//  1. Decide which base image to compare against:
//     - explicit user input (CLI `--base <ref>`),
//     - or auto-detection from OCI labels
//     (`org.opencontainers.image.base.name` etc.),
//     - or BuildKit attestation (deferred — see ADR-0007).
//  2. Open the base image (same source.Factory as the target).
//  3. Compute the diff via internal/image/layer.ComputeDiff.
//  4. For every Component with LayerInfo: assign Origin from the
//     diff. For every Component without LayerInfo: Origin=unknown.
//
// The basediff enricher is graceful: if the base image cannot be
// resolved or pulled, it logs a warning, marks every component
// Origin=unknown, and returns nil. The pipeline continues — basediff
// is augmentation, not a hard gate.
package basediff

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Mode controls how the enricher resolves the base image.
type Mode int

const (
	// ModeAuto reads the base image reference from the target's
	// OCI labels. Default.
	ModeAuto Mode = iota
	// ModeExplicit uses the supplied Reference verbatim.
	ModeExplicit
	// ModeNone skips basediff entirely (Origin stays empty).
	ModeNone
	// ModePartial is an internal-only fallback used when ModeAuto
	// found a base reference in the labels but image.Open could not
	// pull / read it. The enricher uses the target's own layer count
	// as a heuristic ("base = every layer except the last") and
	// stamps each component's `astinus:basediff:confidence=low` so
	// the consumer can tell. Better than the all-Unknown failure
	// mode this used to degrade to.
	// post-Stage-13 hardening Task 3.
	ModePartial
)

// Labels the auto-detector reads, in priority order. The first
// non-empty value wins.
var autoLabels = []string{
	"org.opencontainers.image.base.name",
	"org.opencontainers.image.base.ref.name", // older spelling, seen in some CI builders
}

// digestLabels are queried after the name labels to refine an
// already-detected base reference with a digest pin.
var digestLabels = []string{
	"org.opencontainers.image.base.digest",
}

// detectFromLabels returns the base reference recorded in the image
// config's Labels map, or "" when no recognised label is present.
//
// The returned string has the form "<name>" or "<name>@<digest>" when
// both labels are populated.
func detectFromLabels(cfg *v1.ConfigFile) string {
	if cfg == nil {
		return ""
	}
	labels := cfg.Config.Labels
	if labels == nil {
		return ""
	}

	name := firstNonEmpty(labels, autoLabels)
	if name == "" {
		return ""
	}
	if digest := firstNonEmpty(labels, digestLabels); digest != "" {
		// If the name already pins a digest, leave it.
		if !strings.Contains(name, "@") {
			return name + "@" + digest
		}
	}
	return name
}

func firstNonEmpty(m map[string]string, keys []string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
