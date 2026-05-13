package basediff

import (
	"context"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// chainWalkCap bounds the parent_base walk so a circular catalogue
// entry (data corruption) can't wedge the detector. Sprint-6 task
// spec calibrated 5; production base chains are 1-2 levels deep in
// practice (e.g. python:3.13-slim-bookworm → debian:bookworm-slim
// is depth 2). ADR-0061.
const chainWalkCap = 5

// BaseChain is the resolved layered-base hierarchy for one image.
// Level 0 is the most-specific base (the one
// `AutoDetector.Detect` returned), Level N is the deepest parent.
// Empty Levels means no chain was resolvable. S6 Task 4 / ADR-0061.
type BaseChain struct {
	// Levels is the chain from most-specific to least-specific.
	// Each entry is a pointer into KnownBases's slice; do not
	// mutate.
	Levels []*KnownBaseEntry

	// Origin is the result of the underlying Detect call that
	// seeded the chain — preserved so callers can stamp the same
	// detection metadata the single-level path already emits.
	Origin *AutoDetectionResult
}

// IsEmpty reports whether the chain has zero resolved levels —
// shorthand for the common "no chain available" check.
func (c *BaseChain) IsEmpty() bool { return c == nil || len(c.Levels) == 0 }

// DetectChain runs AutoDetector.Detect, then walks the resolved
// entry's `parent_base` link up to `chainWalkCap` times. Returns
// an empty (non-nil) BaseChain when detection produced no base or
// the detected ref isn't in the catalogue.
//
// Errors are reserved for I/O failures (image config unreadable) —
// a no-match result is success with an empty chain. S6 Task 4 /
// ADR-0061.
func (d *AutoDetector) DetectChain(ctx context.Context, img v1.Image) (*BaseChain, error) {
	immediate, err := d.Detect(ctx, img)
	if err != nil {
		return nil, err
	}
	chain := &BaseChain{Origin: immediate}
	if immediate.BaseImageRef == "" || d.known == nil {
		return chain, nil
	}

	cur := d.known.FindByRef(immediate.BaseImageRef)
	if cur == nil {
		// Detected ref not in our catalogue under that exact
		// spelling. The caller still gets immediate metadata via
		// chain.Origin; no chain levels.
		return chain, nil
	}
	chain.Levels = append(chain.Levels, cur)

	seen := map[string]bool{cur.ImageRef: true}
	for i := 0; i < chainWalkCap; i++ {
		if cur.ParentBase == "" {
			break
		}
		parent := d.known.FindByRef(cur.ParentBase)
		if parent == nil {
			break
		}
		if seen[parent.ImageRef] {
			// Cycle in the catalogue (data bug). Stop the walk;
			// we already have the entries up to the cycle point.
			break
		}
		chain.Levels = append(chain.Levels, parent)
		seen[parent.ImageRef] = true
		cur = parent
	}
	return chain, nil
}

// ClassifyByAddedPackages reports whether the component was
// introduced by any level of the chain. Returns the matching level
// + ref (0-based, 0 = most-specific) when one of the chain levels
// lists c.Name in its AddedPackages. Returns (0, "", false) on a
// miss — the caller falls back to its existing classification.
// Today we match on package NAME only (the spec calibrated this
// against deb-package shape where exact name+version match is
// often unreliable across upgrades within the same base lineage).
// ADR-0061.
func (c *BaseChain) ClassifyByAddedPackages(name string) (int, string, bool) {
	if c == nil || name == "" {
		return 0, "", false
	}
	for level, entry := range c.Levels {
		if entry == nil {
			continue
		}
		for _, pkg := range entry.AddedPackages {
			if pkg == name {
				return level, entry.ImageRef, true
			}
		}
	}
	return 0, "", false
}
