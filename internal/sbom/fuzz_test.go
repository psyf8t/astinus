package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDetectBytes asserts the format detector cannot panic regardless
// of input shape. Seeded from the on-disk SBOM fixtures plus a small
// catalogue of crafted edge cases (BOMs, truncations, garbage).
//
// post-stage-13 review F-006.
func FuzzDetectBytes(f *testing.F) {
	// Seed: the canonical-format-passing fixtures.
	seedFixtures(f, "..", "..", "test", "fixtures", "sboms")

	// Seed: crafted edges.
	for _, s := range [][]byte{
		nil,
		{},
		{0x00},
		{0xEF, 0xBB, 0xBF}, // bare UTF-8 BOM
		{0xFF, 0xFE},       // bare UTF-16 LE BOM
		{0xFE, 0xFF},       // bare UTF-16 BE BOM
		[]byte("{"),
		[]byte("<"),
		[]byte("SPDXVersion:"),
		[]byte(`{"bomFormat":"`),
		[]byte(`<?xml version="1.0"?><other></other>`),
		[]byte("not an SBOM\n"),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: must not panic. Both error and format are
		// allowed; any combination of (format, err) is fine as long
		// as the function returns instead of crashing.
		_, _ = DetectBytes(data)
	})
}

// seedFixtures recursively walks the given path under the project root
// and adds every regular file's contents to the fuzz corpus.
func seedFixtures(f *testing.F, parts ...string) {
	f.Helper()
	root := filepath.Join(parts...)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // missing fixture is fine; skip rather than abort seeding
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // fixture path under repo
		if readErr != nil {
			return nil //nolint:nilerr // unreadable fixture is fine; skip rather than abort seeding
		}
		f.Add(body)
		return nil
	})
}
