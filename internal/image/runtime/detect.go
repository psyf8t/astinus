package runtime

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Runtime is the identity of the build tool that produced an image.
//
// RuntimeUnknown is reserved for the case where Detect could not even
// load the image config — every successful Detect call returns one of
// the named runtimes (RuntimeDocker as the documented fallback).
type Runtime string

// Recognised build runtimes.
const (
	RuntimeDocker   Runtime = "docker"
	RuntimeBuildKit Runtime = "buildkit"
	RuntimePodman   Runtime = "podman"
	RuntimeBuildah  Runtime = "buildah"
	RuntimeKaniko   Runtime = "kaniko"
	RuntimeJib      Runtime = "jib"
	RuntimeKo       Runtime = "ko"
	RuntimeUnknown  Runtime = "unknown"
)

// DetectionEvidence is one observed signal that contributed to the
// runtime decision. Returned in priority order — the first entry is
// the strongest signal the detector saw.
type DetectionEvidence struct {
	// Field identifies where the signal lives in the OCI artefact
	// (e.g. "config.Author", "config.Labels[moby.buildkit.frontend]",
	// "history[3].CreatedBy", "manifest.annotations[...]").
	Field string

	// Value is the observed value, captured verbatim so the operator
	// can see exactly what triggered the match.
	Value string

	// Reason is a short human-readable phrase describing why this
	// evidence implies the chosen runtime.
	Reason string
}

// detector is the internal interface every per-runtime classifier
// implements. The first detector to return ok=true wins.
type detector interface {
	detect(img v1.Image, cf *v1.ConfigFile, mf *v1.Manifest) (Runtime, []DetectionEvidence, bool)
}

// detectors lists the per-runtime classifiers in priority order.
//
// BuildKit goes first because its provenance-attestation signal is
// the strongest and we want it to take precedence over labels that
// could have been copied between builds. Kaniko, Jib, and Ko go next
// because they leave very specific signatures. Podman/Buildah are
// last among the named runtimes because their signature ("buildah"
// in history strings) is the easiest to spoof. Docker is the
// documented fallback when nothing else matches.
var detectors = []detector{
	buildKitDetector{},
	kanikoDetector{},
	jibDetector{},
	koDetector{},
	podmanBuildahDetector{},
}

// Detect identifies the runtime that built img and returns the
// evidence that drove the decision.
//
// The detector chain walks fixed-priority entries; the first match
// wins. When nothing matches, Detect returns (RuntimeDocker, nil, nil)
// — Docker is the documented fallback for OCI-compliant images that
// carry no other runtime fingerprint.
//
// A non-nil error means the image config could not be read; the
// returned runtime is RuntimeUnknown in that case so callers can
// distinguish a fallback ("looked, found nothing distinctive") from
// a failure ("could not look at all").
func Detect(img v1.Image) (Runtime, []DetectionEvidence, error) {
	if img == nil {
		return RuntimeUnknown, nil, fmt.Errorf("runtime: nil image")
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return RuntimeUnknown, nil, fmt.Errorf("runtime: read config: %w", err)
	}
	// Manifest is optional — some sources may legitimately fail it
	// (e.g. partially constructed images in tests). When unavailable,
	// pass nil so detectors fall back to config-only signals.
	mf, _ := img.Manifest()

	for _, d := range detectors {
		if rt, ev, ok := d.detect(img, cf, mf); ok {
			return rt, ev, nil
		}
	}
	return RuntimeDocker, nil, nil
}

// ─── BuildKit ─────────────────────────────────────────────────────────────

type buildKitDetector struct{}

func (buildKitDetector) detect(_ v1.Image, cf *v1.ConfigFile, mf *v1.Manifest) (Runtime, []DetectionEvidence, bool) {
	// Strongest signal: a sibling attestation manifest. We only see
	// this when the caller hands us the attestation manifest itself
	// (which carries `vnd.docker.reference.type=attestation-manifest`)
	// — the platform image manifest does not. Detecting it here is
	// still useful for callers that explicitly inspect the
	// attestation manifest.
	if mf != nil {
		if v, ok := mf.Annotations["vnd.docker.reference.type"]; ok && v == "attestation-manifest" {
			return RuntimeBuildKit, []DetectionEvidence{{
				Field:  "manifest.annotations[vnd.docker.reference.type]",
				Value:  v,
				Reason: "image is a BuildKit attestation manifest",
			}}, true
		}
	}

	// Strong signal: any moby.buildkit.* label. BuildKit stamps these
	// labels into every image it produces.
	if cf != nil {
		for k, v := range cf.Config.Labels {
			if strings.HasPrefix(k, "moby.buildkit") {
				return RuntimeBuildKit, []DetectionEvidence{{
					Field:  fmt.Sprintf("config.Labels[%s]", k),
					Value:  v,
					Reason: "moby.buildkit.* label present",
				}}, true
			}
		}
	}

	// Medium signal: history.CreatedBy with the BuildKit-specific
	// "buildkit.dockerfile.v0" frontend marker that buildctl emits.
	if cf != nil {
		for i, h := range cf.History {
			if strings.Contains(h.CreatedBy, "buildkit.dockerfile.v") {
				return RuntimeBuildKit, []DetectionEvidence{{
					Field:  fmt.Sprintf("history[%d].CreatedBy", i),
					Value:  h.CreatedBy,
					Reason: "history mentions buildkit.dockerfile frontend",
				}}, true
			}
		}
	}

	return "", nil, false
}

// ─── Kaniko ───────────────────────────────────────────────────────────────

type kanikoDetector struct{}

func (kanikoDetector) detect(img v1.Image, cf *v1.ConfigFile, _ *v1.Manifest) (Runtime, []DetectionEvidence, bool) {
	if cf == nil {
		return "", nil, false
	}

	// Strongest signal: the Author field. Kaniko hard-codes "Kaniko".
	if cf.Author == "Kaniko" {
		return RuntimeKaniko, []DetectionEvidence{{
			Field:  "config.Author",
			Value:  cf.Author,
			Reason: "Kaniko sets the Author field to its own name",
		}}, true
	}

	// Strong signal: the OCI builder label. Kaniko users sometimes
	// override the author but keep the label.
	if v, ok := cf.Config.Labels["org.opencontainers.image.builder"]; ok {
		if strings.Contains(strings.ToLower(v), "kaniko") {
			return RuntimeKaniko, []DetectionEvidence{{
				Field:  "config.Labels[org.opencontainers.image.builder]",
				Value:  v,
				Reason: "OCI image.builder label names Kaniko",
			}}, true
		}
	}

	// Weak signal: a squashed layout — many history entries collapsed
	// into a few layers. Kaniko's default behaviour is to squash; so
	// is `docker build --squash`, so the evidence label calls this
	// out as low-confidence. We only flip the bit when the ratio is
	// extreme (5+ history → ≤2 layers).
	if layers, err := img.Layers(); err == nil {
		if len(cf.History) >= 5 && len(layers) <= 2 {
			return RuntimeKaniko, []DetectionEvidence{{
				Field:  "heuristic.squash",
				Value:  fmt.Sprintf("history=%d layers=%d", len(cf.History), len(layers)),
				Reason: "many history entries but few layers (Kaniko or `docker build --squash`)",
			}}, true
		}
	}

	return "", nil, false
}

// ─── Jib ──────────────────────────────────────────────────────────────────

type jibDetector struct{}

// jibLayerNames mirrors the four canonical layers Jib lays down for
// a Java application: dependencies, snapshot-dependencies, resources,
// classes. Real Jib images may contain additional layers from extra
// directories, but these four are present in the documented order.
var jibLayerNames = []string{"dependencies", "resources", "classes"}

func (jibDetector) detect(_ v1.Image, cf *v1.ConfigFile, _ *v1.Manifest) (Runtime, []DetectionEvidence, bool) {
	if cf == nil {
		return "", nil, false
	}

	// Strong signal: the jib.image.* label namespace.
	for k, v := range cf.Config.Labels {
		if strings.HasPrefix(k, "jib.image.") || strings.HasPrefix(k, "com.google.cloud.tools.jib") {
			return RuntimeJib, []DetectionEvidence{{
				Field:  fmt.Sprintf("config.Labels[%s]", k),
				Value:  v,
				Reason: "Jib-specific label present",
			}}, true
		}
	}

	// Medium signal: history.CreatedBy strings naming Jib's layer
	// types in order. Jib emits one history entry per layer with the
	// layer kind in the comment.
	hits := 0
	for _, h := range cf.History {
		for _, name := range jibLayerNames {
			if strings.Contains(h.CreatedBy, "jib-"+name) || strings.Contains(h.Comment, "jib-"+name) {
				hits++
				break
			}
		}
	}
	if hits >= 2 {
		return RuntimeJib, []DetectionEvidence{{
			Field:  "history.CreatedBy",
			Value:  fmt.Sprintf("matched %d Jib layer markers", hits),
			Reason: "history names Jib's canonical layer kinds",
		}}, true
	}

	return "", nil, false
}

// ─── Ko ───────────────────────────────────────────────────────────────────

type koDetector struct{}

func (koDetector) detect(_ v1.Image, cf *v1.ConfigFile, _ *v1.Manifest) (Runtime, []DetectionEvidence, bool) {
	if cf == nil {
		return "", nil, false
	}

	for k, v := range cf.Config.Labels {
		if strings.HasPrefix(k, "ko.build.") || k == "dev.ko.build" {
			return RuntimeKo, []DetectionEvidence{{
				Field:  fmt.Sprintf("config.Labels[%s]", k),
				Value:  v,
				Reason: "ko.build.* label present",
			}}, true
		}
	}

	// Ko sets the OCI image.source label and uses /ko-app as the
	// canonical entrypoint location. Both together are a reliable
	// signal even when ko's own labels are stripped.
	source, hasSource := cf.Config.Labels["org.opencontainers.image.source"]
	hasKoApp := false
	for _, cmd := range cf.Config.Entrypoint {
		if strings.HasPrefix(cmd, "/ko-app/") {
			hasKoApp = true
			break
		}
	}
	if hasSource && hasKoApp {
		return RuntimeKo, []DetectionEvidence{{
			Field:  "config.Entrypoint+config.Labels",
			Value:  fmt.Sprintf("entrypoint=/ko-app/* source=%s", source),
			Reason: "Ko's canonical /ko-app entrypoint plus image.source label",
		}}, true
	}

	return "", nil, false
}

// ─── Podman / Buildah ─────────────────────────────────────────────────────

type podmanBuildahDetector struct{}

func (podmanBuildahDetector) detect(_ v1.Image, cf *v1.ConfigFile, _ *v1.Manifest) (Runtime, []DetectionEvidence, bool) {
	if cf == nil {
		return "", nil, false
	}

	// Buildah stamps history.Author = "Buildah" or its specific
	// "buildah build" marker in CreatedBy.
	for i, h := range cf.History {
		if strings.EqualFold(h.Author, "buildah") {
			return RuntimeBuildah, []DetectionEvidence{{
				Field:  fmt.Sprintf("history[%d].Author", i),
				Value:  h.Author,
				Reason: "Buildah stamps its name into history.Author",
			}}, true
		}
		lower := strings.ToLower(h.CreatedBy)
		switch {
		case strings.Contains(lower, "/usr/bin/buildah"), strings.HasPrefix(lower, "buildah:"):
			return RuntimeBuildah, []DetectionEvidence{{
				Field:  fmt.Sprintf("history[%d].CreatedBy", i),
				Value:  h.CreatedBy,
				Reason: "history.CreatedBy mentions buildah",
			}}, true
		case strings.HasPrefix(lower, "containers-storage:"):
			// Both Podman and Buildah pull through containers-storage;
			// the plain prefix without an explicit "buildah" marker
			// is more often Podman than Buildah in practice.
			return RuntimePodman, []DetectionEvidence{{
				Field:  fmt.Sprintf("history[%d].CreatedBy", i),
				Value:  h.CreatedBy,
				Reason: "history.CreatedBy uses containers-storage transport",
			}}, true
		case strings.HasPrefix(lower, "podman:"), strings.Contains(lower, "/usr/bin/podman"):
			return RuntimePodman, []DetectionEvidence{{
				Field:  fmt.Sprintf("history[%d].CreatedBy", i),
				Value:  h.CreatedBy,
				Reason: "history.CreatedBy mentions podman",
			}}, true
		}
	}

	return "", nil, false
}
