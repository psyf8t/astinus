package basediff

import "github.com/psyf8t/astinus/internal/image/layer"

// fakePrefixDiff is a tiny shim that builds a layer.Diff value
// without going through ComputeDiff. The cross-package test in
// enricher_test.go uses it to drive stampOrigin in isolation.
type fakePrefixDiff struct {
	prefix int
}

func (f *fakePrefixDiff) into() *layer.Diff {
	return &layer.Diff{Mode: layer.DiffModePrefix, BasePrefix: f.prefix}
}

// fakeFallbackDiff builds a fallback-mode diff with a fixed set of
// "this path was in the base" entries. Used by Task 3 tests to
// drive originFor without standing up a real second image.
type fakeFallbackDiff struct {
	basePaths map[string]bool
}

func (f *fakeFallbackDiff) into() *layer.Diff {
	return &layer.Diff{Mode: layer.DiffModeFallback, BasePaths: f.basePaths}
}
