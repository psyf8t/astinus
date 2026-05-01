package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// archiveSource reads images from `docker save`-style tar archives.
//
// The image is loaded lazily on Image() so callers pay for the read
// only when they need it.
type archiveSource struct {
	path    string
	tag     name.Reference
	once    sync.Once
	image   v1.Image
	loadErr error
}

// newArchiveSource validates path exists and returns a source that
// will read it on the first Image() call.
//
// The tag is best-effort — if explicit, it's used; otherwise we
// synthesize "archive:<basename>" so downstream code always has
// something to log.
func newArchiveSource(path string, tag string) (*archiveSource, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("archive: %q: %w", path, ErrNotFound)
		}
		return nil, fmt.Errorf("archive: stat %q: %w", path, err)
	}

	ref, err := archiveReference(path, tag)
	if err != nil {
		return nil, err
	}

	return &archiveSource{path: path, tag: ref}, nil
}

// archiveReference returns the canonical name.Reference for the archive.
// If tag is empty, we synthesize archive:<basename>.
func archiveReference(path, tag string) (name.Reference, error) {
	if tag != "" {
		ref, err := name.ParseReference(tag)
		if err != nil {
			return nil, fmt.Errorf("archive: parse tag %q: %w", tag, err)
		}
		return ref, nil
	}
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		base = "image"
	}
	ref, err := name.ParseReference("archive/" + base + ":latest")
	if err != nil {
		return nil, fmt.Errorf("archive: synthesize reference: %w", err)
	}
	return ref, nil
}

// Reference implements ImageSource.
func (a *archiveSource) Reference() name.Reference { return a.tag }

// Image implements ImageSource.
func (a *archiveSource) Image(_ context.Context) (v1.Image, error) {
	a.once.Do(func() {
		// tarball.ImageFromPath only consults the tag if the archive
		// has multiple manifests; for single-image tars (the
		// overwhelming common case) tag may be nil.
		var tag *name.Tag
		if t, ok := a.tag.(name.Tag); ok {
			tag = &t
		}
		a.image, a.loadErr = tarball.ImageFromPath(a.path, tag)
		if a.loadErr != nil {
			a.loadErr = fmt.Errorf("archive: load %q: %w", a.path, a.loadErr)
		}
	})
	return a.image, a.loadErr
}

// Close implements ImageSource. tarball.ImageFromPath opens the file
// each time the layer is read, so we have nothing persistent to close.
func (a *archiveSource) Close() error { return nil }
