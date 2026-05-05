package attribution

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
	"github.com/psyf8t/astinus/internal/image/runtime"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestAttributionStampsLayerInfo(t *testing.T) {
	img := buildImage(t, []map[string]string{
		{"usr/bin/foo": "v1"},                         // layer 0
		{"opt/app/jq": "binary", "etc/hostname": "h"}, // layer 1
	})
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef: "comp-foo",
				Name:   "foo",
				Evidence: &model.Evidence{
					Locations: []model.EvidenceLocation{{Path: "/usr/bin/foo"}},
				},
			},
			{
				BOMRef: "comp-jq",
				Name:   "jq",
				Evidence: &model.Evidence{
					Locations: []model.EvidenceLocation{{Path: "opt/app/jq"}},
				},
			},
		},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if sbom.Components[0].LayerInfo == nil || sbom.Components[0].LayerInfo.LayerIndex != 0 {
		t.Errorf("foo layer = %+v, want layer 0", sbom.Components[0].LayerInfo)
	}
	if sbom.Components[1].LayerInfo == nil || sbom.Components[1].LayerInfo.LayerIndex != 1 {
		t.Errorf("jq layer = %+v, want layer 1", sbom.Components[1].LayerInfo)
	}
}

func TestAttributionLatestLayerWins(t *testing.T) {
	img := buildImage(t, []map[string]string{
		{"usr/bin/foo": "v1"},
		{"usr/bin/foo": "v2"},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:   "c",
			Name:     "foo",
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "/usr/bin/foo"}}},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Components[0].LayerInfo.LayerIndex != 1 {
		t.Errorf("LayerIndex = %d, want 1 (latest layer wins)", sbom.Components[0].LayerInfo.LayerIndex)
	}
}

func TestAttributionSquashedSingleLayer(t *testing.T) {
	img := buildImage(t, []map[string]string{
		{"a": "1", "b": "2"},
	})
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "a", Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "a"}}}},
			{Name: "b", Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "b"}}}},
		},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for _, c := range sbom.Components {
		if c.LayerInfo == nil || c.LayerInfo.LayerIndex != 0 {
			t.Errorf("component %q LayerInfo = %+v, want layer 0", c.Name, c.LayerInfo)
		}
	}
}

func TestAttributionLeavesUnknownPathsAlone(t *testing.T) {
	img := buildImage(t, []map[string]string{
		{"a": "1"},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name:     "ghost",
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "/no/such/file"}}},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Components[0].LayerInfo != nil {
		t.Errorf("LayerInfo should be nil for unknown path, got %+v", sbom.Components[0].LayerInfo)
	}
}

func TestAttributionNoEvidenceLeavesNil(t *testing.T) {
	img := buildImage(t, []map[string]string{{"a": "1"}})
	sbom := &model.SBOM{
		Components: []model.Component{{Name: "no-evidence"}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Components[0].LayerInfo != nil {
		t.Errorf("LayerInfo should be nil")
	}
}

func TestAttributionPreservesExistingLayerInfo(t *testing.T) {
	img := buildImage(t, []map[string]string{{"a": "1"}})
	preExisting := &model.LayerInfo{LayerIndex: 99, AddedBy: "manual"}
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name:      "x",
			Evidence:  &model.Evidence{Locations: []model.EvidenceLocation{{Path: "a"}}},
			LayerInfo: preExisting,
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Components[0].LayerInfo != preExisting {
		t.Error("existing LayerInfo should be preserved (idempotent / non-destructive)")
	}
}

func TestAttributionRecursesIntoSubComponents(t *testing.T) {
	img := buildImage(t, []map[string]string{{"opt/app/lib.jar": "x"}})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "outer",
			SubComponents: []model.Component{{
				Name:     "lib",
				Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "opt/app/lib.jar"}}},
			}},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Components[0].SubComponents[0].LayerInfo == nil {
		t.Error("sub-component should have LayerInfo populated")
	}
}

func TestAttributionRequiresImage(t *testing.T) {
	if err := New().Enrich(context.Background(), &model.SBOM{}, &image.Bundle{}); err == nil {
		t.Fatal("expected error when bundle.Image is nil")
	}
}

func TestAttributionName(t *testing.T) {
	if New().Name() != "attribution" {
		t.Errorf("Name = %q", New().Name())
	}
}

func TestAttributionStampsRuntimeAndConfidence(t *testing.T) {
	img := buildImage(t, []map[string]string{{"a": "1"}})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "x", Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "a"}}},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	bundle.Runtime = "kaniko"
	bundle.RuntimeEvidence = []runtime.DetectionEvidence{{
		Field: "config.Author", Value: "Kaniko", Reason: "exact author match",
	}}

	// Replace normalize with a fixed Kaniko-shaped layer set so the
	// test does not depend on the real go-containerregistry layer
	// reading (which the build helpers above do exercise — but here
	// we want to assert the stamping behaviour deterministically).
	e := New()
	e.normalizeFn = func(_ runtime.Runtime, _ *image.Bundle) ([]runtime.NormalizedLayer, error) {
		return []runtime.NormalizedLayer{{
			Index:           0,
			CreatedBy:       "RUN apt-get && build && copy",
			RuntimeMetadata: map[string]string{"squashed": "likely"},
		}}, nil
	}

	if err := e.Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := sbom.Metadata.Properties[model.PropertyRuntime]; got != "kaniko" {
		t.Errorf("PropertyRuntime = %q, want kaniko", got)
	}
	if got := sbom.Metadata.Properties[model.PropertyAttributionConfidence]; got != "low" {
		t.Errorf("PropertyAttributionConfidence = %q, want low", got)
	}
	if got := sbom.Metadata.Properties[model.PropertyAttributionReason]; got == "" {
		t.Error("PropertyAttributionReason must not be empty")
	}
	if got := sbom.Metadata.Properties[model.PropertyRuntimeEvidence]; got == "" {
		t.Error("PropertyRuntimeEvidence must not be empty when evidence is present")
	}
}

func TestAttributionRuntimeStampDefaultsToUnknown(t *testing.T) {
	img := buildImage(t, []map[string]string{{"a": "1"}})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "x", Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "a"}}},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/x:1"), img, sbom)
	// Bundle.Runtime intentionally left zero — we want unknown.

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := sbom.Metadata.Properties[model.PropertyRuntime]; got != "unknown" {
		t.Errorf("PropertyRuntime = %q, want unknown", got)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func buildImage(t *testing.T, layers []map[string]string) v1.Image {
	t.Helper()
	img := empty.Image
	for _, files := range layers {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buildTar(t, files))), nil
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
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustTag(t *testing.T, ref string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}
