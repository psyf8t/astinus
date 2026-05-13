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
//
// S5 Task 2 split the single `Digest` field into the canonical
// pair the OCI image-spec defines: `DiffID` (sha256 of the
// uncompressed tar — `rootfs.diff_ids` entry in the image
// config) and `CompressedDigest` (sha256 of the compressed blob
// — `manifest.layers[].digest`). The two values differ; the
// pre-S5 code only emitted CompressedDigest and labelled it as
// `astinus:layer:digest`, which downstream consumers couldn't
// map to a manifest layer because run #3 benchmark showed
// 0/20 sample accuracy against the GT's diff_id.
type Info struct {
	// Index is the 0-based layer index (bottom layer is 0).
	Index int

	// DiffID is the sha256 of the uncompressed tar — the
	// canonical layer identifier per the OCI image-spec
	// (`rootfs.diff_ids[i]`). Stable across compression scheme
	// changes (gzip ↔ zstd) and across `docker save` /
	// `crane pull` / `skopeo copy`. Empty when
	// go-containerregistry could not surface it (rare; the
	// uncompressed Reader has to be drained).
	DiffID string

	// CompressedDigest is the sha256 of the compressed blob as
	// stored in the OCI manifest (`manifest.layers[].digest`).
	// Useful for registry-blob lookups but NOT canonical across
	// re-compressions. Empty when the backend can't provide it
	// (some OCI-layout / daemon paths).
	CompressedDigest string

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
//
// S5 Task 2: populates DiffID (canonical OCI layer identifier from
// `rootfs.diff_ids`) AND CompressedDigest (registry blob hash from
// `manifest.layers[].digest`). Pre-S5 code only stored
// CompressedDigest, mislabeled as `astinus:layer:digest` for SBOM
// consumers — run #3 benchmark showed 0/20 sample-accuracy match
// against the ground truth's diff_id because the two are distinct
// sha256 values for the same layer.
func buildInfos(img v1.Image, layers []v1.Layer) ([]Info, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}

	infos := make([]Info, len(layers))
	for i, lyr := range layers {
		// Compressed digest — the manifest blob hash. Cheap;
		// go-containerregistry caches it on the Layer.
		if d, err := lyr.Digest(); err == nil {
			infos[i].CompressedDigest = d.String()
		}
		// DiffID — the canonical OCI identifier. Read from
		// rootfs.diff_ids when available (every image config
		// carries it), fall back to lyr.DiffID() when the
		// config-side ordering doesn't line up.
		if cfg != nil && i < len(cfg.RootFS.DiffIDs) {
			infos[i].DiffID = cfg.RootFS.DiffIDs[i].String()
		} else if d, err := lyr.DiffID(); err == nil {
			infos[i].DiffID = d.String()
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

// NormalizePath is the package's path-normalisation helper, exported
// so cross-package callers (the basediff content strategy) can match
// FileMap keys without re-implementing the same canonicalisation.
//
// Returns "" for "" and ".". See normalizePath for the full rule set.
func NormalizePath(p string) string { return normalizePath(p) }

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
