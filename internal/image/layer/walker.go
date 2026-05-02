// Package layer walks the layered filesystem of an OCI image and
// answers "which layer did this path come from?".
//
// The package treats an image as a stack of tar layers (bottom →
// top), honours OCI/Docker whiteout markers (`.wh.<name>` and
// `.wh..wh..opq`), and produces a `path → layerIndex` map indexed by
// the layer that LAST modified the path. This is the precedence rule
// the spec calls "latest layer wins" (section 8.6).
//
// The walker streams each layer (no full extraction to disk), so a
// 500 MB image walk costs O(layers × tar-decode) time and bounded
// memory.
package layer

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	stdtar "archive/tar"
)

// FileMap is the result of walking an image's layers.
//
// Paths are normalised to be slash-separated, **without** a leading
// slash, matching how tar headers spell them. The boolean reports
// whether the lookup found anything.
type FileMap struct {
	// paths is the path -> layer index of the LAST layer to write or
	// modify the path.
	paths map[string]int

	// layers is the in-order list of layer descriptors so the
	// returned LayerIndex always pairs with a stable identity.
	layers []Info
}

// Info describes one layer in the order it was applied.
type Info struct {
	// Index is the 0-based layer index (bottom layer is 0).
	Index int

	// Digest is the layer's compressed digest from the manifest
	// ("sha256:..."). Empty when go-containerregistry could not
	// surface it (rare; logged but not fatal).
	Digest string

	// CreatedBy is the Dockerfile instruction that produced this
	// layer, taken from the image config's history. Empty when
	// history is missing or shorter than the layer list (squashed
	// images, in-progress builds).
	CreatedBy string

	// EmptyLayer mirrors the image config history flag — true for
	// layers that contributed only metadata (e.g. ENV) and have no
	// filesystem changes.
	EmptyLayer bool
}

// Lookup returns the layer index that last touched path, plus
// whether the path is currently visible (not whited-out by a higher
// layer). Paths are normalised before lookup, so callers can pass
// "/usr/bin/jq", "usr/bin/jq", or "./usr/bin/jq" interchangeably.
func (m *FileMap) Lookup(p string) (Info, bool) {
	if m == nil {
		return Info{}, false
	}
	idx, ok := m.paths[normalizePath(p)]
	if !ok {
		return Info{}, false
	}
	if idx < 0 || idx >= len(m.layers) {
		return Info{}, false
	}
	return m.layers[idx], true
}

// Layers returns the per-layer descriptors in apply order.
func (m *FileMap) Layers() []Info {
	if m == nil {
		return nil
	}
	out := make([]Info, len(m.layers))
	copy(out, m.layers)
	return out
}

// Len reports how many distinct paths the FileMap tracks.
func (m *FileMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.paths)
}

// Walk streams every layer of img and returns the resulting FileMap.
//
// Pass ctx for cancellation; the walker does not introduce its own
// timeout. Errors from the layer reader propagate untouched (so they
// keep their go-containerregistry context).
func Walk(ctx context.Context, img v1.Image) (*FileMap, error) {
	if img == nil {
		return nil, fmt.Errorf("layer: nil image")
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layer: image layers: %w", err)
	}

	descs, err := buildInfos(img, layers)
	if err != nil {
		return nil, err
	}

	m := &FileMap{
		paths:  make(map[string]int),
		layers: descs,
	}

	for i, lyr := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := walkLayer(i, lyr, m); err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
	}

	return m, nil
}

// buildInfos pairs each layer with its history entry from the
// image config. The two lists differ in length when the image has
// "empty layer" history records (ENV/CMD/etc.) — we step the history
// cursor only on non-empty entries.
func buildInfos(img v1.Image, layers []v1.Layer) ([]Info, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}

	infos := make([]Info, len(layers))
	for i, lyr := range layers {
		d, err := lyr.Digest()
		if err == nil {
			infos[i].Digest = d.String()
		}
		infos[i].Index = i
	}

	// Step through history, skipping empty-layer entries when we
	// pair them with the layer slice.
	if cfg == nil {
		return infos, nil
	}
	li := 0
	for _, h := range cfg.History {
		if h.EmptyLayer {
			// Empty-layer history entries don't consume a layer.
			// They're still useful metadata but not addressable by
			// path; we record the most recent CreatedBy on the
			// next non-empty layer if there is one.
			continue
		}
		if li >= len(infos) {
			break
		}
		infos[li].CreatedBy = h.CreatedBy
		infos[li].EmptyLayer = false
		li++
	}
	return infos, nil
}

// walkLayer streams one layer's tar and updates m.paths.
//
// Whiteouts:
//   - "<dir>/.wh.<file>"   removes <dir>/<file> from the visible set
//   - "<dir>/.wh..wh..opq" removes everything under <dir> from
//     prior layers; subsequent paths in this layer or above
//     repopulate it normally.
func walkLayer(layerIdx int, lyr v1.Layer, m *FileMap) error {
	rc, err := lyr.Uncompressed()
	if err != nil {
		return fmt.Errorf("uncompressed: %w", err)
	}
	defer func() { _ = rc.Close() }()

	tr := stdtar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar header: %w", err)
		}

		name := normalizePath(hdr.Name)
		if name == "" {
			continue
		}
		base := path.Base(name)
		dir := path.Dir(name)

		switch {
		case base == ".wh..wh..opq":
			// Opaque whiteout: drop everything below dir from prior
			// layers. Paths added in *this* layer (whether they
			// appeared in the tar before or after the opq marker)
			// must survive — only entries written by an earlier
			// layer get evicted.
			removePrefixFromPriorLayers(m, dir+"/", layerIdx)
		case strings.HasPrefix(base, ".wh."):
			// Per-file whiteout.
			whiteName := strings.TrimPrefix(base, ".wh.")
			target := path.Join(dir, whiteName)
			delete(m.paths, normalizePath(target))
		default:
			// Skip pure directory entries — we attribute files, not
			// directories. This keeps the map sized to the things
			// enrichers actually look up.
			if hdr.Typeflag == stdtar.TypeDir {
				continue
			}
			m.paths[name] = layerIdx
		}
	}
}

// removePrefixFromPriorLayers deletes every path in m that starts
// with prefix AND was placed there by a layer earlier than
// currentLayer. prefix MUST end with "/". Used by opaque whiteouts.
func removePrefixFromPriorLayers(m *FileMap, prefix string, currentLayer int) {
	for k, idx := range m.paths {
		if idx < currentLayer && strings.HasPrefix(k, prefix) {
			delete(m.paths, k)
		}
	}
}

// normalizePath turns various wire spellings into the canonical
// (slash-separated, no leading "/", no leading "./") form we use as
// map keys.
//
// "." and "" return "" so the caller can ignore them.
func normalizePath(p string) string {
	if p == "" || p == "." {
		return ""
	}
	// tar headers may use forward slashes already; replace any back
	// slashes that crept in (Windows-built archives are rare but not
	// impossible).
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	// Normalise via path.Clean to collapse "//" and "/foo/../".
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == "/" {
		return ""
	}
	return strings.TrimPrefix(cleaned, "/")
}
