package spdx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzReadJSON asserts the SPDX JSON reader cannot panic on any
// input. Seeded from the SPDX JSON fixtures.
//
// post-stage-13 review F-006.
func FuzzReadJSON(f *testing.F) {
	root := filepath.Join("..", "..", "..", "test", "fixtures", "sboms", "spdx")
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

	for _, s := range [][]byte{
		nil,
		{},
		[]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x"}`),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadJSON(bytes.NewReader(data))
	})
}

// FuzzReadTagValue covers the SPDX tag-value parser. No on-disk
// fixtures yet — seeded from a minimal valid document plus crafted
// edges.
func FuzzReadTagValue(f *testing.F) {
	for _, s := range [][]byte{
		nil,
		{},
		[]byte("SPDXVersion: SPDX-2.3\n"),
		[]byte("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: x\nDocumentNamespace: http://example.com/x\n"),
		[]byte("SPDXVersion:"),
		[]byte("SPDXVersion: \n\n\n\n\n"),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadTagValue(bytes.NewReader(data))
	})
}
