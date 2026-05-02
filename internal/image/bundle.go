// Package image is the integration point between the SBOM model and
// the OCI image readers under internal/image/source.
//
// A Bundle holds everything an enricher needs in one struct: the
// canonical SBOM it operates on, the v1.Image whose layers it walks,
// the originating reference, and the underlying ImageSource so the
// caller (CLI, tests) can release it via Bundle.Close.
//
// Sub-packages:
//
//	internal/image/source    — ImageSource implementations (registry, archive, …)
//	internal/image/auth      — credential providers
//	internal/image/transport — HTTP RoundTripper construction
//	internal/image/layer     — layer-level walking and extraction
package image

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/psyf8t/astinus/internal/image/source"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Bundle pairs the canonical SBOM with the loaded v1.Image and the
// originating ImageSource. Enrichers receive *Bundle so they don't
// have to know whether the image came from a registry, a tarball, or
// (Stage 8+) a daemon.
type Bundle struct {
	// Reference is the canonical image reference.
	Reference name.Reference

	// Source is the underlying ImageSource. Bundle.Close releases it.
	// Nil for callers that build a Bundle from an in-memory v1.Image
	// (e.g. tests).
	Source source.ImageSource

	// Image is the loaded v1.Image. Always non-nil after Open.
	Image v1.Image

	// SBOM is the canonical SBOM the pipeline mutates. Always non-nil
	// after Open. Owned by the Bundle — enrichers mutate in place.
	SBOM *model.SBOM
}

// Open loads the image referenced by ref, pairs it with sbom, and
// returns the resulting Bundle. The bundle's Source must be released
// by the caller via Close (typically `defer bundle.Close()`).
//
// sbom must not be nil. ref is forwarded to source.FromReference, so
// every reference shape that package accepts works here too.
func Open(ctx context.Context, ref string, sbom *model.SBOM, opts ...source.Option) (*Bundle, error) {
	if sbom == nil {
		return nil, fmt.Errorf("image: nil sbom")
	}
	src, err := source.FromReference(ctx, ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("image: open source: %w", err)
	}
	img, err := src.Image(ctx)
	if err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("image: load image %q: %w", ref, err)
	}
	return &Bundle{
		Reference: src.Reference(),
		Source:    src,
		Image:     img,
		SBOM:      sbom,
	}, nil
}

// NewBundle builds a Bundle from an already-loaded v1.Image. Useful
// in tests where the image comes from random.Image and no Source
// exists. Reference and Source may be zero-valued.
func NewBundle(ref name.Reference, img v1.Image, sbom *model.SBOM) *Bundle {
	return &Bundle{Reference: ref, Image: img, SBOM: sbom}
}

// Close releases the underlying ImageSource. Safe to call on a nil
// Bundle and on a Bundle without a Source (returns nil in both cases).
func (b *Bundle) Close() error {
	if b == nil || b.Source == nil {
		return nil
	}
	return b.Source.Close()
}
