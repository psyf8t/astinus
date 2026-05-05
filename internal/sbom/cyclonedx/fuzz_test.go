package cyclonedx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sbompkg "github.com/psyf8t/astinus/internal/sbom"
)

// FuzzReadJSON asserts the CycloneDX JSON reader cannot panic on any
// input. Seeded from the seven hand-rolled CycloneDX fixtures.
//
// post-stage-13 review F-006.
func FuzzReadJSON(f *testing.F) {
	root := filepath.Join("..", "..", "..", "test", "fixtures", "sboms", "cyclonedx")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil //nolint:nilerr // missing/non-JSON fixture is fine; skip rather than abort seeding
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // fixture path under repo
		if readErr != nil {
			return nil //nolint:nilerr // unreadable fixture is fine; skip rather than abort seeding
		}
		f.Add(body)
		return nil
	})

	// Crafted edges.
	for _, s := range [][]byte{
		nil,
		{},
		[]byte(`{`),
		[]byte(`{"bomFormat":"CycloneDX"`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`),
		[]byte(strings.Repeat("{", 1024)),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Reject inputs above the SBOM cap up front; we only fuzz the
		// in-range parser surface.
		if len(data) > sbompkg.MaxSBOMBytes {
			t.Skip("input larger than MaxSBOMBytes")
		}
		// Contract: must not panic. Returning an error is fine.
		// `ErrSBOMTooLarge` should never come through (we capped above)
		// but checking it explicitly documents the intent.
		_, err := ReadJSON(bytes.NewReader(data))
		if errors.Is(err, sbompkg.ErrSBOMTooLarge) {
			t.Fatalf("size cap unexpectedly tripped on %d-byte input", len(data))
		}
	})
}
