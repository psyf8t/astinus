package source

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// fakeSource implements ImageSource for the bundle tests so we don't
// need a real registry/archive.
type fakeSource struct {
	closed bool
	ref    name.Reference
}

func (f *fakeSource) Reference() name.Reference { return f.ref }
func (f *fakeSource) Image(_ context.Context) (v1.Image, error) {
	return nil, errFakeSourceNoImage
}
func (f *fakeSource) Close() error { f.closed = true; return nil }

var errFakeSourceNoImage = errors.New("fakeSource: image not provided")

func TestBundleCloseDelegates(t *testing.T) {
	tag, _ := name.NewTag("test/x:1")
	fs := &fakeSource{ref: tag}
	b := &Bundle{Source: fs}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fs.closed {
		t.Error("expected fakeSource.Close to be called")
	}
}

func TestBundleCloseNilSafe(t *testing.T) {
	var b *Bundle
	if err := b.Close(); err != nil {
		t.Fatalf("Close on nil bundle: %v", err)
	}
	if err := (&Bundle{}).Close(); err != nil {
		t.Fatalf("Close on bundle with nil source: %v", err)
	}
}
