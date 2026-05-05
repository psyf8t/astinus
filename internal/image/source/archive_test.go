package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestArchiveSourceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "tiny.tar")
	tag := mustTag(t, "test/tiny:v1")
	img := mustRandomImage(t, 256, 1)

	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	src, err := newArchiveSource(tarPath, "test/tiny:v1")
	if err != nil {
		t.Fatalf("newArchiveSource: %v", err)
	}
	defer src.Close()

	if got := src.Reference().Name(); got != "index.docker.io/test/tiny:v1" {
		t.Errorf("Reference = %q", got)
	}

	loaded, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if _, err := loaded.Manifest(); err != nil {
		t.Errorf("Manifest from loaded image: %v", err)
	}
}

func TestArchiveSourceMissingFile(t *testing.T) {
	_, err := newArchiveSource("/no/such/file.tar", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestArchiveSourceSyntheticReference(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(tarPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := newArchiveSource(tarPath, "")
	if err != nil {
		t.Fatalf("newArchiveSource: %v", err)
	}
	defer src.Close()
	got := src.Reference().Name()
	if got != "index.docker.io/archive/image:latest" {
		t.Errorf("synthesized reference = %q", got)
	}
}

func TestArchiveSourceLoadFailure(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "broken.tar")
	if err := os.WriteFile(tarPath, []byte("not a real tar archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := newArchiveSource(tarPath, "")
	if err != nil {
		t.Fatalf("newArchiveSource: %v", err)
	}
	if _, err := src.Image(context.Background()); err == nil {
		t.Fatal("expected error loading non-tar bytes")
	}
}

// ─── Test helpers ──────────────────────────────────────────────────────────

func mustTag(t *testing.T, ref string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatalf("name.NewTag: %v", err)
	}
	return tag
}

func mustRandomImage(t *testing.T, size, layers int64) v1.Image {
	t.Helper()
	img, err := random.Image(size, layers)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	return img
}
