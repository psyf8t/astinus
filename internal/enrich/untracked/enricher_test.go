package untracked

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/psyf8t/astinus/internal/fingerprint"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEnrichAddsExecutable(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/foo": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "foo" || c.Type != model.ComponentTypeApplication {
		t.Errorf("comp = %+v", c)
	}
	if c.Properties["astinus:untracked:category"] != "executable" {
		t.Errorf("category = %q", c.Properties["astinus:untracked:category"])
	}
	if c.Evidence == nil || c.Evidence.Method != "untracked-scan" {
		t.Errorf("evidence = %+v", c.Evidence)
	}
	if c.LayerInfo == nil {
		t.Errorf("LayerInfo should be populated")
	}
	if len(c.Hashes) == 0 || c.Hashes[0].Algorithm != model.HashAlgorithmSHA256 {
		t.Errorf("hashes = %+v", c.Hashes)
	}
}

func TestEnrichSkipsKnownPaths(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/known": {0x7f, 'E', 'L', 'F'},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "known",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "opt/bin/known"}},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("components = %d, want 1 (no untracked added)", len(sbom.Components))
	}
}

func TestEnrichSkipsKnownPathsWithLeadingSlash(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/known": {0x7f, 'E', 'L', 'F'},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "known",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "/opt/bin/known"}},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("components = %d, want 1 (leading slash should normalize)", len(sbom.Components))
	}
}

func TestEnrichSkipsNoise(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"usr/share/man/man1/foo.1": []byte("man page"),
		"app/__pycache__/x.pyc":    []byte("\x00pyc\x00"),
		"opt/lib/libstatic.a":      []byte("ar archive"),
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("components = %d, want 0 (all noise)", len(sbom.Components))
	}
}

func TestEnrichRecognisesJAR(t *testing.T) {
	jar := buildJAR(t, "Bundle-SymbolicName: com.example.jar\r\nBundle-Version: 2.0.0\r\n\r\n")
	img := buildImage(t, map[string][]byte{"opt/app/lib.jar": jar})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "com.example.jar" || c.Version != "2.0.0" {
		t.Errorf("jar metadata not applied: %+v", c)
	}
	if c.Type != model.ComponentTypeLibrary {
		t.Errorf("jar type = %v, want library", c.Type)
	}
}

func TestEnrichAppliesMatcher(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/jq": []byte("\x7fELF jq fake bytes"),
	})

	// Build the matcher BEFORE running Enrich; we need the file's
	// SHA-256 to register the lookup. Re-use Hasher to compute it.
	bytesIn := []byte("\x7fELF jq fake bytes")
	digest := sha256Hex(t, bytesIn)

	local := matcher.NewLocalMatcher()
	local.Add(model.HashAlgorithmSHA256, digest, matcher.Match{
		Name: "jq", Version: "1.7.1", PURL: "pkg:generic/jq@1.7.1",
		CPEs:   []string{"cpe:2.3:a:jqlang:jq:1.7.1:*:*:*:*:*:*:*"},
		Source: "test-local",
	})

	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{Matcher: local}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "jq" || c.Version != "1.7.1" || c.PURL == "" {
		t.Errorf("matcher fields not applied: %+v", c)
	}
	if c.Evidence.Method != "fingerprint" {
		t.Errorf("evidence method = %q, want 'fingerprint'", c.Evidence.Method)
	}
	if c.Properties["astinus:untracked:matcher"] != "test-local" {
		t.Errorf("matcher source missing: %v", c.Properties)
	}
}

func TestEnrichRespectsMaxComponents(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		key := "opt/bin/" + string(rune('a'+i))
		files[key] = []byte{0x7f, 'E', 'L', 'F', byte(i)}
	}
	img := buildImage(t, files)
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{MaxComponents: 2}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("components = %d, want 2 (cap honoured)", len(sbom.Components))
	}
}

func TestEnrichRequiresImage(t *testing.T) {
	if err := New().Enrich(context.Background(), &model.SBOM{}, &image.Bundle{}); err == nil {
		t.Fatal("expected error when bundle.Image is nil")
	}
}

func TestEnricherName(t *testing.T) {
	if New().Name() != Name {
		t.Errorf("Name = %q", New().Name())
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func buildImage(t *testing.T, files map[string][]byte) v1.Image {
	t.Helper()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buildTar(t, files))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func buildTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: path, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildJAR(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustTag(t *testing.T) name.Tag {
	t.Helper()
	tag, err := name.NewTag("test/x:1")
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func sha256Hex(t *testing.T, b []byte) string {
	t.Helper()
	hex, _, err := fingerprint.HashSHA256(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return hex
}
