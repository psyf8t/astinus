package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// buildLayoutDir builds a tiny OCI image layout on disk and returns
// the directory.
func buildLayoutDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	idxPath, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatalf("layout.Write: %v", err)
	}
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := idxPath.AppendImage(img); err != nil {
		t.Fatalf("AppendImage: %v", err)
	}
	return dir
}

func TestLayoutSourceLoad(t *testing.T) {
	dir := buildLayoutDir(t)
	src, err := newLayoutSource(dir, Options{})
	if err != nil {
		t.Fatalf("newLayoutSource: %v", err)
	}
	defer src.Close()

	img, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if _, err := img.Manifest(); err != nil {
		t.Errorf("Manifest: %v", err)
	}
}

func TestLayoutSourceMissingIndex(t *testing.T) {
	dir := t.TempDir()
	_, err := newLayoutSource(dir, Options{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLayoutSourceMissingMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newLayoutSource(dir, Options{})
	if err == nil {
		t.Fatal("expected error for missing oci-layout marker")
	}
}

func TestLayoutSourceReferenceSynthesised(t *testing.T) {
	dir := buildLayoutDir(t)
	src, err := newLayoutSource(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := src.Reference().Name()
	if got == "" || filepath.Base(dir) == "" {
		t.Fatalf("Reference = %q (dir=%q)", got, dir)
	}
}

func TestPickManifestFallback(t *testing.T) {
	if got := pickManifest(nil, ""); got != 0 {
		t.Errorf("pickManifest empty = %d, want 0", got)
	}
}
