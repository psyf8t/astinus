package layer

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ─── Path normalization ───────────────────────────────────────────────────

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                "",
		".":               "",
		"/":               "",
		"./":              "",
		"./usr/bin/jq":    "usr/bin/jq",
		"/usr/bin/jq":     "usr/bin/jq",
		"usr//bin/jq":     "usr/bin/jq",
		"usr/./bin/jq":    "usr/bin/jq",
		"usr/bin/../sbin": "usr/sbin",
		"usr\\bin\\jq":    "usr/bin/jq",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── Walker over hand-crafted layered images ──────────────────────────────

func TestWalkSingleLayer(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "v1", "etc/hostname": "host"}},
	})
	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if m.Len() != 2 {
		t.Errorf("Len = %d, want 2", m.Len())
	}
	li, ok := m.Lookup("/usr/bin/foo")
	if !ok || li.Index != 0 {
		t.Errorf("Lookup foo = (%v,%v), want layer 0", li, ok)
	}
}

func TestWalkLatestLayerWins(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "v1"}},
		{files: map[string]string{"usr/bin/foo": "v2", "usr/bin/bar": "b"}},
	})
	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if li, _ := m.Lookup("usr/bin/foo"); li.Index != 1 {
		t.Errorf("foo layer = %d, want 1 (latest wins)", li.Index)
	}
	if li, _ := m.Lookup("usr/bin/bar"); li.Index != 1 {
		t.Errorf("bar layer = %d, want 1", li.Index)
	}
}

func TestWalkPerFileWhiteout(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "v1", "usr/bin/bar": "b"}},
		{whiteouts: []string{"usr/bin/foo"}},
	})
	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if _, ok := m.Lookup("usr/bin/foo"); ok {
		t.Errorf("foo should be whited out")
	}
	if _, ok := m.Lookup("usr/bin/bar"); !ok {
		t.Errorf("bar should still be visible")
	}
}

func TestWalkOpaqueWhiteout(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"opt/app/a": "1", "opt/app/b": "2", "etc/hostname": "h"}},
		{opaqueWhiteouts: []string{"opt/app"}, files: map[string]string{"opt/app/c": "3"}},
	})
	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if _, ok := m.Lookup("opt/app/a"); ok {
		t.Errorf("opt/app/a should be removed by opaque whiteout")
	}
	if _, ok := m.Lookup("opt/app/b"); ok {
		t.Errorf("opt/app/b should be removed")
	}
	if li, ok := m.Lookup("opt/app/c"); !ok || li.Index != 1 {
		t.Errorf("opt/app/c should be present at layer 1, got (%v,%v)", li, ok)
	}
	if _, ok := m.Lookup("etc/hostname"); !ok {
		t.Errorf("/etc/hostname should survive (different prefix)")
	}
}

func TestWalkEmptyImage(t *testing.T) {
	img := empty.Image
	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk empty: %v", err)
	}
	if m.Len() != 0 {
		t.Errorf("empty image map should be empty, got %d", m.Len())
	}
	if got := m.Layers(); len(got) != 0 {
		t.Errorf("empty image layers slice = %v", got)
	}
}

func TestWalkContextCanceled(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"x": "y"}},
		{files: map[string]string{"a": "b"}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Walk(ctx, img); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestWalkNilImage(t *testing.T) {
	if _, err := Walk(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil image")
	}
}

// ─── Image fixture helpers ────────────────────────────────────────────────

type layerSpec struct {
	files           map[string]string
	whiteouts       []string
	opaqueWhiteouts []string
}

// buildImage constructs an in-memory image with one tar layer per
// layerSpec (in order, bottom→top).
func buildImage(t *testing.T, specs []layerSpec) v1.Image {
	t.Helper()
	img := empty.Image
	for _, s := range specs {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buildLayerTar(t, s))), nil
		})
		if err != nil {
			t.Fatalf("LayerFromOpener: %v", err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatalf("AppendLayers: %v", err)
		}
	}
	return mutate.MediaType(img, types.OCIManifestSchema1)
}

// buildLayerTar serialises a layerSpec into a tar byte stream.
func buildLayerTar(t *testing.T, s layerSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, content := range s.files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range s.whiteouts {
		dir, base := splitDirBase(p)
		writeMarker(t, tw, dir+"/.wh."+base)
	}
	for _, dir := range s.opaqueWhiteouts {
		writeMarker(t, tw, dir+"/.wh..wh..opq")
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func writeMarker(t *testing.T, tw *tar.Writer, name string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o000,
		Typeflag: tar.TypeReg,
		Size:     0,
	}); err != nil {
		t.Fatal(err)
	}
}

// splitDirBase yields ("dir", "base") for "dir/base" inputs. For
// inputs without "/", returns (".", input).
func splitDirBase(p string) (string, string) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i], p[i+1:]
		}
	}
	return ".", p
}

// ─── FileMap surface ─────────────────────────────────────────────────────

func TestFileMapNilSafe(t *testing.T) {
	var m *FileMap
	if _, ok := m.Lookup("anything"); ok {
		t.Error("nil FileMap should return ok=false")
	}
	if m.Layers() != nil {
		t.Error("nil FileMap.Layers should be nil")
	}
	if m.Len() != 0 {
		t.Error("nil FileMap.Len should be 0")
	}
}
