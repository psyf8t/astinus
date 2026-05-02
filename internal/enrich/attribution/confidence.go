package attribution

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psyf8t/astinus/internal/image/runtime"
)

// Confidence is the qualitative confidence Astinus has in the layer
// attribution it stamped on Components.
//
// The value is per-image (not per-component) because the underlying
// signals — whether the image was squashed, whether SLSA provenance is
// available, whether image history is intact — apply uniformly across
// every component.
type Confidence string

// Confidence levels emitted as PropertyAttributionConfidence.
const (
	// ConfidenceHigh — per-instruction attribution is reliable. Set
	// when SLSA provenance is available (BuildKit) or when each
	// layer pairs with a non-empty history entry.
	ConfidenceHigh Confidence = "high"

	// ConfidenceMedium — per-layer attribution is reliable but
	// per-instruction is best-effort. The default for normal Docker
	// builds with intact history.
	ConfidenceMedium Confidence = "medium"

	// ConfidenceLow — attribution is approximate. Set when the
	// image was squashed (Kaniko default, `docker build --squash`)
	// or when history is missing entirely.
	ConfidenceLow Confidence = "low"

	// ConfidenceNone — attribution is unattributable. Reserved for
	// images where even the layer count cannot be determined.
	ConfidenceNone Confidence = "none"
)

// HasProvenance is the test the confidence rule applies to determine
// whether the BuildKit-with-provenance path is taken. We accept it as
// a function rather than a bool so the test suite (and integration
// code that has the actual provenance) can wire in real detection
// without confidence having to import the provenance package
// directly.
type HasProvenance func() bool

// DetermineConfidence chooses a Confidence level for the supplied
// normalized layers and runtime, returning a short human-readable
// reason that explains the choice.
//
// The reason string is consumer-facing — it lands in
// PropertyAttributionReason.
func DetermineConfidence(layers []runtime.NormalizedLayer, rt runtime.Runtime, hasProvenance HasProvenance) (Confidence, string) {
	switch {
	case hasProvenance != nil && hasProvenance():
		return ConfidenceHigh, "BuildKit SLSA provenance attestation is present"
	case len(layers) == 0:
		return ConfidenceNone, "image has no layers"
	case rt == runtime.RuntimeKaniko:
		// Kaniko's quirk metadata is the authoritative signal.
		// Some Kaniko builds (e.g. with `--single-snapshot=false`
		// and few RUN steps) preserve granularity, but the
		// safe default is "low".
		return ConfidenceLow, fmt.Sprintf("image was built with Kaniko (%d layers, squashing likely)", len(layers))
	case looksSquashed(layers):
		return ConfidenceLow, fmt.Sprintf("image is squashed (%d layers, no per-instruction history)", len(layers))
	case hasFullHistory(layers):
		return ConfidenceMedium, "history aligns with every layer"
	default:
		return ConfidenceLow, "history is missing or partial"
	}
}

// EvidenceSummary returns a deterministic, human-readable rendering
// of the evidence slice — used as the value of PropertyRuntimeEvidence
// so an operator inspecting the SBOM can see why Astinus picked the
// runtime it picked.
func EvidenceSummary(evidence []runtime.DetectionEvidence) string {
	if len(evidence) == 0 {
		return ""
	}
	parts := make([]string, 0, len(evidence))
	for _, e := range evidence {
		parts = append(parts, fmt.Sprintf("%s=%q (%s)", e.Field, truncate(e.Value, 64), e.Reason))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// looksSquashed flags a layer set with one or two layers and history
// entries on every layer that look like RUN-with-many-commands. The
// heuristic catches `docker build --squash` even when the runtime
// detector did not pick it as Kaniko.
func looksSquashed(layers []runtime.NormalizedLayer) bool {
	if len(layers) > 2 {
		return false
	}
	for _, l := range layers {
		if l.RuntimeMetadata["squashed"] == "likely" {
			return true
		}
	}
	return false
}

// hasFullHistory reports whether every layer was paired with a
// non-empty CreatedBy during normalisation.
func hasFullHistory(layers []runtime.NormalizedLayer) bool {
	for _, l := range layers {
		if l.CreatedBy == "" {
			return false
		}
	}
	return true
}

// truncate clips s to n runes with an ellipsis. Used so a noisy
// CreatedBy string does not blow up the evidence summary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
