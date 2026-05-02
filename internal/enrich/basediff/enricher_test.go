package basediff

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
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

// TestStampOriginFallback_PathMatchesWithoutLayerInfo — the
// post-Stage-13 hardening fix. Before, `originFor` returned
// OriginUnknown for every component without LayerInfo, which is
// most of what Syft produces. Now fallback mode falls through to
// path matching even with LayerInfo == nil.
func TestStampOriginFallback_PathMatchesWithoutLayerInfo(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		// Syft-shaped: location in syft:location:N:path properties.
		{
			Name: "lodash",
			Properties: map[string]string{
				"syft:location:0:path": "/app/node_modules/lodash/package.json",
			},
		},
		// Astinus-shaped: location in Evidence.Locations.
		{
			Name: "system-thing",
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{
				{Path: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
			}},
		},
		// Component without any path info — falls through to app.
		{Name: "no-paths"},
	}}
	diff := (&fakeFallbackDiff{basePaths: map[string]bool{
		"usr/lib/x86_64-linux-gnu/libc.so.6": true,
	}}).into()

	stampOrigin(sbom, diff)

	if got := sbom.Components[0].Origin; got != model.OriginApplication {
		t.Errorf("lodash (app code) = %q, want application", got)
	}
	if got := sbom.Components[1].Origin; got != model.OriginBaseImage {
		t.Errorf("libc.so.6 (in base) = %q, want base-image", got)
	}
	if got := sbom.Components[2].Origin; got != model.OriginApplication {
		t.Errorf("no-paths = %q, want application (no signal → app default)", got)
	}
}

// TestPathsForComponent_ReadsBothShapes — the helper must surface
// paths from BOTH Evidence.Locations and syft:location:N:path
// properties. Mirrors the equivalent test in untracked/filter_test.
func TestPathsForComponent_ReadsBothShapes(t *testing.T) {
	c := &model.Component{
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "/from/evidence"}},
		},
		Properties: map[string]string{
			"syft:location:0:path":    "/from/syft-prop-0",
			"syft:location:1:path":    "/from/syft-prop-1",
			"syft:location:0:layerID": "sha256:cafebabe",
			"syft:package:type":       "npm",
		},
	}
	got := pathsForComponent(c)

	want := map[string]bool{
		"/from/evidence":    true,
		"/from/syft-prop-0": true,
		"/from/syft-prop-1": true,
	}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want 3", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
}

// TestEnrichLogsFallbackWithReason — the diagnostic line operators
// look for when basediff downgrades. Captures the slog default and
// asserts the warn record carries reason + advice.
func TestEnrichLogsFallbackWithReason(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	sbom := sampleSBOM()
	img := buildImageWithLayers(t, layerOf("a", "1"))
	bundle := image.NewBundle(mustTag(t), img, sbom)

	// ModeAuto + image with no labels → "no-base-label" fallback.
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"basediff.fallback"`) {
		t.Errorf("missing basediff.fallback record: %s", out)
	}
	if !strings.Contains(out, `"reason":"no-base-label"`) {
		t.Errorf("missing reason=no-base-label: %s", out)
	}
	if !strings.Contains(out, `"advice"`) {
		t.Errorf("missing advice field: %s", out)
	}
}

// TestStampOriginPartialStampsLowConfidence — when the partial-mode
// helper is used, every component gets a confidence=low property
// stamp so the consumer knows the basediff result is heuristic.
func TestStampOriginPartialStampsLowConfidence(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "a", LayerInfo: &model.LayerInfo{LayerIndex: 0}},
		{Name: "b", LayerInfo: &model.LayerInfo{LayerIndex: 5}},
	}}
	diff := (&fakePrefixDiff{prefix: 2}).into()
	stampOriginWithMode(sbom, diff, ModePartial)

	for _, c := range sbom.Components {
		if c.Properties["astinus:basediff:confidence"] != "low" {
			t.Errorf("component %q confidence = %q, want low",
				c.Name, c.Properties["astinus:basediff:confidence"])
		}
	}
}

// TestModeStringCovers ensures every Mode value has a stable label
// — exhaustive switch for the diffModeString style.
func TestModeStringCovers(t *testing.T) {
	cases := []struct {
		m    Mode
		want string
	}{
		{ModeAuto, "auto"},
		{ModeExplicit, "explicit"},
		{ModeNone, "none"},
		{ModePartial, "partial"},
	}
	for _, c := range cases {
		if got := modeString(c.m); got != c.want {
			t.Errorf("modeString(%d) = %q, want %q", c.m, got, c.want)
		}
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
