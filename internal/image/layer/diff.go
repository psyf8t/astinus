package layer

import (
	"context"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// DiffMode is how confident the diff is about which target layers
// belong to the base image.
type DiffMode int

const (
	// DiffModePrefix means the first N layer digests of the target
	// match the base image's layers exactly. Layer index < N belongs
	// to the base; index >= N belongs to the application. This is
	// the cheap, accurate, and overwhelmingly common case.
	DiffModePrefix DiffMode = iota
	// DiffModeFallback means the prefix did not match (squashed or
	// rebased target). The diff falls back to "every path that the
	// base image also has gets Origin=base; everything else gets
	// Origin=app". Less precise (a modified file at the same path
	// gets misclassified as base) but still useful.
	DiffModeFallback
)

// Diff is the result of comparing a target image against its base.
type Diff struct {
	// Mode tells the caller which discrimination strategy applies.
	Mode DiffMode

	// BasePrefix is the number of leading target layers that came
	// from the base image (prefix mode). Always 0 in fallback mode.
	BasePrefix int

	// BasePaths is the set of file paths the base image carries
	// (populated only in fallback mode). Keys use the same canonical
	// form as FileMap.
	BasePaths map[string]bool
}

// IsBaseLayer reports whether the given target layer index belongs
// to the base image, per the prefix discrimination.
func (d *Diff) IsBaseLayer(targetLayerIdx int) bool {
	if d == nil {
		return false
	}
	if d.Mode != DiffModePrefix {
		return false
	}
	return targetLayerIdx < d.BasePrefix
}

// IsBasePath reports whether the given path is present in the base
// image's filesystem (fallback mode). Used when the layer prefix did
// not match.
func (d *Diff) IsBasePath(path string) bool {
	if d == nil || len(d.BasePaths) == 0 {
		return false
	}
	return d.BasePaths[normalizePath(path)]
}

// ComputeDiff compares two images by layer digest. When the base's
// digest sequence is a strict prefix of the target's, the result is
// DiffModePrefix with BasePrefix == len(base.Layers). Otherwise the
// result is DiffModeFallback with BasePaths populated by walking the
// base image.
//
// Pass ctx for cancellation; ComputeDiff does not introduce its own
// timeout. Both images must be non-nil.
func ComputeDiff(ctx context.Context, target, base v1.Image) (*Diff, error) {
	if target == nil {
		return nil, fmt.Errorf("layer: nil target image")
	}
	if base == nil {
		return nil, fmt.Errorf("layer: nil base image")
	}

	tgtLayers, err := target.Layers()
	if err != nil {
		return nil, fmt.Errorf("layer: target layers: %w", err)
	}
	baseLayers, err := base.Layers()
	if err != nil {
		return nil, fmt.Errorf("layer: base layers: %w", err)
	}

	if prefix, ok := layerPrefix(tgtLayers, baseLayers); ok {
		return &Diff{Mode: DiffModePrefix, BasePrefix: prefix}, nil
	}

	// Prefix did not match — walk the base image to build a path set.
	baseMap, err := Walk(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("layer: walk base: %w", err)
	}
	paths := make(map[string]bool, baseMap.Len())
	for p := range baseMap.paths {
		paths[p] = true
	}
	return &Diff{Mode: DiffModeFallback, BasePaths: paths}, nil
}

// layerPrefix reports whether the first len(base) layers of target
// have the same digests as base. Returns the matched prefix length
// and true on success.
//
// Treats a digest call error as "no match" (degrade gracefully —
// some images are constructed without per-layer digests in fixtures).
func layerPrefix(target, base []v1.Layer) (int, bool) {
	if len(base) == 0 {
		// Zero-layer base trivially matches any target. The caller
		// gets BasePrefix = 0, meaning everything is "app".
		return 0, true
	}
	if len(target) < len(base) {
		return 0, false
	}
	for i, b := range base {
		bd, err := b.Digest()
		if err != nil {
			return 0, false
		}
		td, err := target[i].Digest()
		if err != nil {
			return 0, false
		}
		if bd != td {
			return 0, false
		}
	}
	return len(base), true
}
