package image

import (
	"context"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"

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
