package image

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/psyf8t/astinus/internal/image/runtime"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestNewBundleAndClose(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	tag, _ := name.NewTag("test/x:1")
	sbom := &model.SBOM{}
	b := NewBundle(tag, img, sbom)

	if b.Reference != tag {
		t.Errorf("Reference = %v", b.Reference)
	}
	if b.Image != img {
		t.Errorf("Image not wired")
	}
	if b.SBOM != sbom {
		t.Errorf("SBOM not wired")
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close (no Source) should be nil-safe: %v", err)
	}
}

func TestNilBundleClose(t *testing.T) {
	var b *Bundle
	if err := b.Close(); err != nil {
		t.Errorf("nil Bundle.Close should be safe: %v", err)
	}
}

func TestOpenRejectsNilSBOM(t *testing.T) {
	if _, err := Open(context.Background(), "ghcr.io/foo:latest", nil); err == nil {
		t.Fatal("expected error for nil SBOM")
	}
}

func TestOpenSourceFailure(t *testing.T) {
	// Empty ref bubbles up source.FromReference's error.
	if _, err := Open(context.Background(), "", &model.SBOM{}); err == nil {
		t.Fatal("expected error for empty reference")
	}
}

// TestOpenDetectsRuntime exercises the integration of Open with
// runtime.Detect: an archive image whose config marks it as Kaniko
// must surface RuntimeKaniko on the resulting Bundle.
func TestOpenDetectsRuntime(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("ConfigFile: %v", err)
	}
	cf.Author = "Kaniko"
	stamped, err := mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatalf("mutate.ConfigFile: %v", err)
	}

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "img.tar")
	tag, _ := name.NewTag("archive/img:latest")
	if err := tarball.WriteToFile(tarPath, tag, stamped); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	b, err := Open(context.Background(), tarPath, &model.SBOM{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	if b.Runtime != runtime.RuntimeKaniko {
		t.Errorf("b.Runtime = %q, want %q", b.Runtime, runtime.RuntimeKaniko)
	}
	if len(b.RuntimeEvidence) == 0 {
		t.Error("RuntimeEvidence should not be empty when a detector matched")
	}
}

// TestOpenRuntimeDefaultsToDocker proves the documented fallback —
// a vanilla image with no runtime fingerprint comes through as
// RuntimeDocker.
func TestOpenRuntimeDefaultsToDocker(t *testing.T) {
	img := empty.Image
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "img.tar")
	tag, _ := name.NewTag("archive/img:latest")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	b, err := Open(context.Background(), tarPath, &model.SBOM{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	if b.Runtime != runtime.RuntimeDocker {
		t.Errorf("b.Runtime = %q, want %q", b.Runtime, runtime.RuntimeDocker)
	}
}
