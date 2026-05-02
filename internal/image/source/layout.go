package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// layoutSource reads images from an OCI image-layout directory
// (https://github.com/opencontainers/image-spec/blob/main/image-layout.md).
//
// The directory MUST contain an `index.json` and an `oci-layout`
// marker. By default the source returns the FIRST manifest in the
// index — sufficient for the typical "single image per layout"
// shape Syft / cosign / regctl produce. Multi-arch indexes are
// resolved by the caller via Options.Platform plumbed through
// `pkg/v1/layout.WithPlatform`; if neither side narrows it the
// first manifest still wins (best-effort, mirrors registry
// behaviour for unspecified platforms).
type layoutSource struct {
	path string
	opts Options
	ref  name.Reference

	once    sync.Once
	image   v1.Image
	loadErr error
}

// newLayoutSource validates that path is an OCI layout and returns a
// lazy source. The image is not loaded until Image() is called.
func newLayoutSource(path string, opts Options) (*layoutSource, error) {
	if _, err := os.Stat(filepath.Join(path, "index.json")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("layout: %q has no index.json: %w", path, ErrNotFound)
		}
		return nil, fmt.Errorf("layout: stat index.json in %q: %w", path, err)
	}
	if _, err := os.Stat(filepath.Join(path, "oci-layout")); err != nil {
		return nil, fmt.Errorf("layout: %q missing oci-layout marker: %w", path, err)
	}

	ref, err := name.ParseReference("oci-layout/" + filepath.Base(path) + ":latest")
	if err != nil {
		return nil, fmt.Errorf("layout: synthesize reference: %w", err)
	}
	return &layoutSource{path: path, opts: opts, ref: ref}, nil
}

// Reference implements ImageSource.
func (l *layoutSource) Reference() name.Reference { return l.ref }

// Image implements ImageSource.
func (l *layoutSource) Image(_ context.Context) (v1.Image, error) {
	l.once.Do(func() {
		l.image, l.loadErr = l.loadImage()
	})
	return l.image, l.loadErr
}

// loadImage does the actual layout traversal in one place so the
// Image() wrapper stays small enough to read.
func (l *layoutSource) loadImage() (v1.Image, error) {
	idx, err := layout.ImageIndexFromPath(l.path)
	if err != nil {
		return nil, fmt.Errorf("layout: load index: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("layout: read index manifest: %w", err)
	}
	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("layout: %q index has no manifests", l.path)
	}

	descIdx := pickManifest(manifest.Manifests, l.opts.Platform)
	if descIdx < 0 {
		return nil, fmt.Errorf("layout: no manifest matches platform %q", l.opts.Platform)
	}
	desc := manifest.Manifests[descIdx]

	// Manifest list: drill down once into the first matching child.
	// Anything deeper than two levels is unusual and not auto-resolved.
	if desc.MediaType.IsIndex() {
		return l.loadFromChildIndex(idx, desc.Digest)
	}
	return idx.Image(desc.Digest)
}

func (l *layoutSource) loadFromChildIndex(parent v1.ImageIndex, digest v1.Hash) (v1.Image, error) {
	child, err := parent.ImageIndex(digest)
	if err != nil {
		return nil, fmt.Errorf("layout: load child index: %w", err)
	}
	cm, err := child.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("layout: read child index manifest: %w", err)
	}
	if len(cm.Manifests) == 0 {
		return nil, fmt.Errorf("layout: child index empty")
	}
	cidx := pickManifest(cm.Manifests, l.opts.Platform)
	if cidx < 0 {
		return nil, fmt.Errorf("layout: no child manifest matches platform %q", l.opts.Platform)
	}
	return child.Image(cm.Manifests[cidx].Digest)
}

// Close implements ImageSource. layout sources hold no persistent
// resources beyond what the GC reaps.
func (l *layoutSource) Close() error { return nil }

// pickManifest returns the index of the manifest in mfs that matches
// platform ("os/arch"); returns 0 when platform is empty (any
// platform); returns -1 when nothing matches a non-empty platform.
func pickManifest(mfs []v1.Descriptor, platform string) int {
	if platform == "" {
		return 0
	}
	want, err := v1.ParsePlatform(platform)
	if err != nil || want == nil {
		return 0 // best-effort: fall back to first
	}
	for i, m := range mfs {
		if m.Platform == nil {
			continue
		}
		if want.OS != "" && want.OS != m.Platform.OS {
			continue
		}
		if want.Architecture != "" && want.Architecture != m.Platform.Architecture {
			continue
		}
		return i
	}
	return -1
}
