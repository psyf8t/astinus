//go:build acceptance

package helpers

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// OCIImageWithFiles writes an OCI image layout containing a single
// layer with the given files (path → body), and returns an
// `oci://<dir>` reference. Used by Sprint 4 acceptance tests that
// need to drive specific file shapes through the astinus pipeline
// (a bare ELF for the no-phantom test, an /etc/os-release for the
// base-detection test, etc.). S4 Task 7.
//
// The tar bytes are computed once and captured in the opener
// closure so go-containerregistry's diff-id pre-compute and the
// subsequent layout write see byte-identical content. (Without
// the capture, Go's randomised map iteration produces a
// different ordering on each call, breaking the integrity check.)
func OCIImageWithFiles(tb testing.TB, files map[string][]byte) string {
	tb.Helper()
	dir := tb.TempDir()

	tarBytes := buildTar(tb, files)
	lyr, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(tarBytes)), nil
	})
	if err != nil {
		tb.Fatalf("tarball.LayerFromOpener: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, lyr)
	if err != nil {
		tb.Fatalf("mutate.AppendLayers: %v", err)
	}
	idxPath, err := layout.Write(dir, empty.Index)
	if err != nil {
		tb.Fatalf("layout.Write: %v", err)
	}
	if err := idxPath.AppendImage(img); err != nil {
		tb.Fatalf("AppendImage: %v", err)
	}
	return "oci://" + dir
}

// buildTar serialises files into a one-layer tar payload suitable
// for tarball.LayerFromOpener. Regular files only; no directories,
// symlinks, or whiteouts (Sprint 4 fixtures don't need them).
func buildTar(tb testing.TB, files map[string][]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, body := range files {
		hdr := &tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tb.Fatalf("tar WriteHeader: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			tb.Fatalf("tar Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}
