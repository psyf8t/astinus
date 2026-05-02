package basediff

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEnrichSkipsWhenModeNone(t *testing.T) {
	sbom := sampleSBOM()
	bundle := image.NewBundle(mustTag(t), buildImageWithLayers(t, layerOf("a", "1")), sbom)

	if err := NewWithOptions(Options{Mode: ModeNone}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for _, c := range sbom.Components {
		if c.Origin != "" {
			t.Errorf("component %q origin = %q, want empty", c.Name, c.Origin)
		}
	}
}

func TestEnrichRequiresImage(t *testing.T) {
	if err := New().Enrich(context.Background(), sampleSBOM(), &image.Bundle{}); err == nil {
		t.Fatal("expected error when bundle.Image is nil")
	}
}

func TestEnrichExplicitModeRequiresReference(t *testing.T) {
	sbom := sampleSBOM()
	img := buildImageWithLayers(t, layerOf("a", "1"))
	bundle := image.NewBundle(mustTag(t), img, sbom)

	err := NewWithOptions(Options{Mode: ModeExplicit}).Enrich(context.Background(), sbom, bundle)
	// resolveBaseRef returns an error for missing reference; the
	// enricher logs + downgrades to unknown rather than propagating.
	if err != nil {
		t.Fatalf("Enrich should not error: %v", err)
	}
	if sbom.Components[0].Origin != model.OriginUnknown {
		t.Errorf("Origin = %q, want unknown", sbom.Components[0].Origin)
	}
}

func TestEnrichAutoModeNoLabels(t *testing.T) {
	sbom := sampleSBOM()
	img := buildImageWithLayers(t, layerOf("a", "1"))
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for _, c := range sbom.Components {
		if c.Origin != model.OriginUnknown {
			t.Errorf("component %q origin = %q, want unknown", c.Name, c.Origin)
		}
	}
}

func TestStampOriginPrefixMode(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "base-comp", LayerInfo: &model.LayerInfo{LayerIndex: 0}},
			{Name: "app-comp", LayerInfo: &model.LayerInfo{LayerIndex: 2}},
			{Name: "no-info"}, // LayerInfo nil
		},
	}
	diff := &fakePrefixDiff{prefix: 2}
	stampOrigin(sbom, diff.into())

	if sbom.Components[0].Origin != model.OriginBaseImage {
		t.Errorf("base-comp = %q", sbom.Components[0].Origin)
	}
	if sbom.Components[1].Origin != model.OriginApplication {
		t.Errorf("app-comp = %q", sbom.Components[1].Origin)
	}
	if sbom.Components[2].Origin != model.OriginUnknown {
		t.Errorf("no-info = %q", sbom.Components[2].Origin)
	}
}

func TestStampOriginRecursesIntoSubComponents(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "outer",
			SubComponents: []model.Component{
				{Name: "child-base", LayerInfo: &model.LayerInfo{LayerIndex: 0}},
				{Name: "child-app", LayerInfo: &model.LayerInfo{LayerIndex: 5}},
			},
		}},
	}
	diff := &fakePrefixDiff{prefix: 2}
	stampOrigin(sbom, diff.into())

	if sbom.Components[0].SubComponents[0].Origin != model.OriginBaseImage {
		t.Errorf("child-base = %q", sbom.Components[0].SubComponents[0].Origin)
	}
	if sbom.Components[0].SubComponents[1].Origin != model.OriginApplication {
		t.Errorf("child-app = %q", sbom.Components[0].SubComponents[1].Origin)
	}
}

func TestStampUnknownLeavesExistingOrigin(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "preset", Origin: model.OriginBaseImage},
			{Name: "blank"},
		},
	}
	stampUnknown(sbom)
	if sbom.Components[0].Origin != model.OriginBaseImage {
		t.Errorf("preset Origin should not change, got %q", sbom.Components[0].Origin)
	}
	if sbom.Components[1].Origin != model.OriginUnknown {
		t.Errorf("blank Origin should become unknown, got %q", sbom.Components[1].Origin)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func sampleSBOM() *model.SBOM {
	return &model.SBOM{
		Components: []model.Component{{
			Name: "x",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "a"}},
			},
		}},
	}
}

func buildImageWithLayers(t *testing.T, files ...map[string]string) v1.Image {
	t.Helper()
	img := empty.Image
	for _, f := range files {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buildTar(t, f))), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatal(err)
		}
	}
	return img
}

func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func layerOf(path, content string) map[string]string { return map[string]string{path: content} }

func mustTag(t *testing.T) name.Tag {
	t.Helper()
	tag, err := name.NewTag("test/x:1")
	if err != nil {
		t.Fatal(err)
	}
	return tag
}
