package layer

import (
	stdtar "archive/tar"
	"context"
	"errors"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// FileEntry is one file delivered by WalkFiles.
//
// The reader passed to the visitor is the tar entry's Reader and is
// only valid for the duration of the visitor call. Visitors that need
// to retain the bytes MUST io.ReadAll them before returning. The
// visitor is also free to read only as much as it needs and return —
// WalkFiles drains/skips the rest.
type FileEntry struct {
	// Path is the canonical path (slash-separated, no leading slash).
	Path string

	// Layer is the layer descriptor that LAST modified Path. The
	// bytes the visitor sees come from this layer.
	Layer Info

	// Header is the underlying tar header. Visitors that want
	// permission bits, ownership, modtime read from here.
	Header *stdtar.Header
}

// FileVisitor receives one entry at a time.
//
// Returning a non-nil error halts the walk (the error is wrapped and
// propagated). Use SkipFile to skip the current entry without
// halting; use SkipLayer to skip the rest of the current layer.
type FileVisitor func(ctx context.Context, e FileEntry, body io.Reader) error

// SkipFile is a sentinel a visitor returns to skip the current file
// without halting the walk.
var SkipFile = fmt.Errorf("layer: skip this file") //nolint:errname,staticcheck // sentinel returned for control flow

// WalkFiles streams every visible file in img exactly once, calling
// visitor with the file's bytes and metadata. "Visible" means the
// file is currently present in the layered filesystem (not removed
// by a later whiteout).
//
// Implementation: WalkFiles first runs Walk to build the FileMap
// (which knows which layer last touched each path), then re-streams
// each layer and forwards the tar entry to the visitor only when the
// FileMap reports this layer as the file's owner. That way every
// path is delivered once, with its currently-effective bytes.
//
// WalkFiles silently skips:
//   - directories (the visitor receives only regular files)
//   - whiteout marker files (`.wh.*`)
//   - hardlinks/symlinks/char/block/fifo/sparse entries
//
// pass ctx for cancellation; the walker checks between layers AND
// between tar entries.
func WalkFiles(ctx context.Context, img v1.Image, visitor FileVisitor) error {
	if img == nil {
		return fmt.Errorf("layer: nil image")
	}
	if visitor == nil {
		return fmt.Errorf("layer: nil visitor")
	}

	fm, err := Walk(ctx, img)
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("layer: image layers: %w", err)
	}

	for i, lyr := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := streamLayer(ctx, i, lyr, fm, visitor); err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
	}
	return nil
}

// streamLayer reads layer i and emits visitor calls for every entry
// whose effective owner is i.
func streamLayer(ctx context.Context, idx int, lyr v1.Layer, fm *FileMap, visitor FileVisitor) error {
	rc, err := lyr.Uncompressed()
	if err != nil {
		return fmt.Errorf("uncompressed: %w", err)
	}
	defer func() { _ = rc.Close() }()

	tr := stdtar.NewReader(rc)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar header: %w", err)
		}

		// Skip non-regular entries — visitors only care about file bytes.
		if hdr.Typeflag != stdtar.TypeReg {
			continue
		}
		path := normalizePath(hdr.Name)
		if path == "" {
			continue
		}

		owner, ok := fm.Lookup(path)
		if !ok || owner.Index != idx {
			// Either whited-out by a later layer, or the file was
			// rewritten by a higher layer — skip in this pass.
			continue
		}

		entry := FileEntry{
			Path:   path,
			Layer:  owner,
			Header: hdr,
		}
		if err := visitor(ctx, entry, tr); err != nil {
			if errors.Is(err, SkipFile) {
				continue
			}
			return fmt.Errorf("visitor for %q: %w", path, err)
		}
	}
}
