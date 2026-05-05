//go:build acceptance

package helpers

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// MinimalOCIImage builds a 1-layer 64-byte random OCI image layout
// in dir (or tb.TempDir if empty) and returns an `oci://<dir>`
// reference suitable for passing to `astinus enrich --image`.
//
// Astinus's image source code accepts oci:// for OCI image layout
// directories — no registry pull, no docker daemon, no network.
// This is what makes the Sprint 3 acceptance suite hermetic.
func MinimalOCIImage(tb testing.TB, dir string) string {
	tb.Helper()
	if dir == "" {
		dir = tb.TempDir()
	}
	idxPath, err := layout.Write(dir, empty.Index)
	if err != nil {
		tb.Fatalf("layout.Write: %v", err)
	}
	img, err := random.Image(64, 1)
	if err != nil {
		tb.Fatalf("random.Image: %v", err)
	}
	if err := idxPath.AppendImage(img); err != nil {
		tb.Fatalf("AppendImage: %v", err)
	}
	return "oci://" + dir
}
