package contenthash

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// TestBuildBaseSetIndexesAllVisibleFiles — every file laid down by
// the layered image, indexed once (latest-layer-wins semantics from
// layer.WalkFiles), with the correct hash + path stamped on the
// recovered Evidence.
func TestBuildBaseSetIndexesAllVisibleFiles(t *testing.T) {
	img := buildLayered(t, []layerSpec{
		{files: map[string]string{
			"usr/bin/hello": "v1-hello",
			"etc/foo":       "v1-foo",
		}},
		{files: map[string]string{
			"usr/bin/hello": "v2-hello", // overrides layer 0
			"opt/app":       "v2-app",
		}},
	})

	set, err := BuildBaseSet(context.Background(), img)
	if err != nil {
		t.Fatalf("BuildBaseSet: %v", err)
	}

	cases := []struct {
		path    string
		content string
	}{
		{"usr/bin/hello", "v2-hello"}, // latest layer wins
		{"etc/foo", "v1-foo"},
		{"opt/app", "v2-app"},
	}
	for _, tc := range cases {
		ev, ok := set.Contains(sha256Hex(tc.content))
		if !ok {
			t.Errorf("%s: hash %s not in BaseSet", tc.path, sha256Hex(tc.content))
			continue
		}
		if ev.BasePath != tc.path {
			t.Errorf("%s: BasePath = %q, want %q", tc.path, ev.BasePath, tc.path)
		}
	}
	if !set.HasPath("usr/bin/hello") {
		t.Error("HasPath should be true for indexed path")
	}
}

func TestBuildBaseSetWhiteoutsHidden(t *testing.T) {
	img := buildLayered(t, []layerSpec{
		{files: map[string]string{"usr/bin/hello": "v1"}},
		{whiteouts: []string{"usr/bin/hello"}},
	})
	set, err := BuildBaseSet(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	// The whited-out file must NOT be in the BaseSet.
	if _, ok := set.Contains(sha256Hex("v1")); ok {
		t.Error("whited-out file's hash leaked into BaseSet")
	}
	if set.HasPath("usr/bin/hello") {
		t.Error("whited-out path leaked into HasPath index")
	}
}

func TestBuildBaseSetNilImage(t *testing.T) {
	if _, err := BuildBaseSet(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil image")
	}
}

// ─── ScanTarget ──────────────────────────────────────────────────────

func TestScanTargetReturnsPathHashMap(t *testing.T) {
	img := buildLayered(t, []layerSpec{
		{files: map[string]string{
			"usr/local/bin/myapp": "app-bytes",
			"usr/lib/libc.so":     "libc-bytes",
		}},
	})
	got, err := ScanTarget(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	if got["usr/local/bin/myapp"] != sha256Hex("app-bytes") {
		t.Errorf("hash mismatch for myapp: %s", got["usr/local/bin/myapp"])
	}
	if got["usr/lib/libc.so"] != sha256Hex("libc-bytes") {
		t.Errorf("hash mismatch for libc.so: %s", got["usr/lib/libc.so"])
	}
}

func TestScanTargetNilImage(t *testing.T) {
	if _, err := ScanTarget(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil image")
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────

type layerSpec struct {
	files     map[string]string
	whiteouts []string
}

func buildLayered(t *testing.T, specs []layerSpec) v1.Image {
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
	return img
}

func buildLayerTar(t *testing.T, s layerSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, content := range s.files {
		if err := tw.WriteHeader(&tar.Header{
			Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range s.whiteouts {
		// `.wh.<base>` whiteout marker.
		if err := tw.WriteHeader(&tar.Header{
			Name: dirFor(p) + ".wh." + baseOf(p), Mode: 0o644, Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func dirFor(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i+1]
		}
	}
	return ""
}

func baseOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
