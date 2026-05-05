package basediff

import (
	"context"
	"log/slog"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/basediff/contenthash"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ─── classifyComponent unit tests ──────────────────────────────────

// TestClassifyContentMatch — classic multi-stage / cross-layer case:
// the component lives at a target path that hashes to a hash the
// base image also has (under a different path). Origin must be
// base; matched-base-path must be stamped.
func TestClassifyContentMatch(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	baseSet.Add("h1", contenthash.Evidence{BasePath: "usr/bin/curl-orig", LayerIndex: 0, Size: 1})

	targetHashes := map[string]string{
		"usr/local/bin/curl": "h1", // same content, different path
	}

	c := &model.Component{
		Name: "curl",
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "usr/local/bin/curl"}},
		},
	}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, targetHashes, stats)
	if got != model.OriginBaseImage {
		t.Errorf("Origin = %q, want base", got)
	}
	if c.Properties[model.PropertyBasediffMatchedBasePath] != "usr/bin/curl-orig" {
		t.Errorf("matched-base-path = %q, want usr/bin/curl-orig",
			c.Properties[model.PropertyBasediffMatchedBasePath])
	}
}

// TestClassifyModifiedAtSamePath — target carries a file at a path
// the base image also uses, but the bytes don't match. Origin is
// still base (the component is base-derived), but state=modified.
func TestClassifyModifiedAtSamePath(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	baseSet.Add("h-base", contenthash.Evidence{BasePath: "etc/foo", LayerIndex: 0, Size: 1})

	targetHashes := map[string]string{
		"etc/foo": "h-target", // path matches but bytes differ
	}

	c := &model.Component{
		Name: "foo-config",
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "etc/foo"}},
		},
	}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, targetHashes, stats)
	if got != model.OriginBaseImage {
		t.Errorf("Origin = %q, want base", got)
	}
	if c.Properties[model.PropertyBasediffState] != "modified" {
		t.Errorf("state = %q, want modified",
			c.Properties[model.PropertyBasediffState])
	}
	if c.Properties[model.PropertyBasediffMatchedBasePath] != "" {
		t.Errorf("matched-base-path should NOT be stamped on modified-at-same-path; got %q",
			c.Properties[model.PropertyBasediffMatchedBasePath])
	}
	if stats.modified != 1 {
		t.Errorf("stats.modified = %d, want 1", stats.modified)
	}
}

// TestClassifyApplicationOnly — neither hash nor path matches the
// base. The file is genuinely app-side.
func TestClassifyApplicationOnly(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	baseSet.Add("h-base", contenthash.Evidence{BasePath: "etc/foo"})

	targetHashes := map[string]string{
		"opt/myapp/server": "h-app",
	}

	c := &model.Component{
		Name: "server",
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "opt/myapp/server"}},
		},
	}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, targetHashes, stats)
	if got != model.OriginApplication {
		t.Errorf("Origin = %q, want app", got)
	}
}

// TestClassifyComponentWithoutPaths — a component with no
// Evidence.Locations cannot be classified by content; falls
// through to unknown.
func TestClassifyComponentWithoutPaths(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	c := &model.Component{Name: "no-paths"}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, map[string]string{}, stats)
	if got != model.OriginUnknown {
		t.Errorf("Origin = %q, want unknown", got)
	}
}

// TestClassifyHashWinsOverPath — when one of the component's paths
// has a content match in the base, that wins regardless of whether
// other paths exist-but-differ at the base.
func TestClassifyHashWinsOverPath(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	baseSet.Add("good-hash", contenthash.Evidence{BasePath: "usr/bin/orig", LayerIndex: 0})
	baseSet.Add("path-only", contenthash.Evidence{BasePath: "etc/conflict", LayerIndex: 0})

	targetHashes := map[string]string{
		"etc/conflict":  "different-bytes", // path matches, content doesn't
		"opt/copy/orig": "good-hash",       // content matches via cross-layer copy
	}

	c := &model.Component{
		Name: "x",
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{
				{Path: "etc/conflict"},
				{Path: "opt/copy/orig"},
			},
		},
	}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, targetHashes, stats)
	if got != model.OriginBaseImage {
		t.Errorf("Origin = %q, want base", got)
	}
	if c.Properties[model.PropertyBasediffMatchedBasePath] != "usr/bin/orig" {
		t.Errorf("matched-base-path = %q, want usr/bin/orig",
			c.Properties[model.PropertyBasediffMatchedBasePath])
	}
	// state=modified should NOT be set when a hash hit was found.
	if c.Properties[model.PropertyBasediffState] != "" {
		t.Errorf("state should be empty when hash matched; got %q",
			c.Properties[model.PropertyBasediffState])
	}
}

// TestClassifyReadsSyftLocationProperties — Syft writes file
// locations into `syft:location:N:path` properties; the classifier
// must read both shapes for the same reasons documented in the
// Hardening-Sprint #1 enricher.
func TestClassifyReadsSyftLocationProperties(t *testing.T) {
	baseSet := contenthash.NewBaseSet(10)
	baseSet.Add("h1", contenthash.Evidence{BasePath: "usr/bin/orig", LayerIndex: 0})

	targetHashes := map[string]string{"usr/local/bin/copy": "h1"}

	c := &model.Component{
		Name: "from-syft",
		Properties: map[string]string{
			"syft:location:0:path": "usr/local/bin/copy",
		},
	}
	stats := &contentStats{}
	got := (&Enricher{}).classifyComponent(c, baseSet, targetHashes, stats)
	if got != model.OriginBaseImage {
		t.Errorf("Origin = %q, want base", got)
	}
}

// ─── runContentStrategy: end-to-end with real layered images ───────

// TestRunContentStrategyEndToEnd builds a base image with one file
// and a target image that copies that same file under a different
// path (the multi-stage case). Asserts that the strategy runs,
// stamps the SBOM-level strategy property, and classifies the
// component as base.
func TestRunContentStrategyEndToEnd(t *testing.T) {
	const curlBytes = "this is a fake curl binary"

	baseImg := buildImageWithLayers(t, layerOf("usr/bin/curl", curlBytes))
	targetImg := buildImageWithLayers(t,
		layerOf("usr/bin/orig", curlBytes), // base layer (different path; bytes match)
		layerOf("opt/app/server", "real-app-bytes"),
	)

	sbom := &model.SBOM{
		Components: []model.Component{
			{
				Name: "curl-copy",
				Evidence: &model.Evidence{
					Locations: []model.EvidenceLocation{{Path: "usr/bin/orig"}},
				},
			},
			{
				Name: "server",
				Evidence: &model.Evidence{
					Locations: []model.EvidenceLocation{{Path: "opt/app/server"}},
				},
			},
		},
	}

	bundle := image.NewBundle(mustTag(t), targetImg, sbom)
	baseBundle := image.NewBundle(mustTag(t), baseImg, sbom)

	ok := (&Enricher{}).runContentStrategy(
		context.Background(), slog.Default(), sbom, bundle, baseBundle, "test/base:1",
	)
	if !ok {
		t.Fatal("runContentStrategy returned false; expected success")
	}

	if sbom.Components[0].Origin != model.OriginBaseImage {
		t.Errorf("curl-copy Origin = %q, want base", sbom.Components[0].Origin)
	}
	if sbom.Components[0].Properties[model.PropertyBasediffMatchedBasePath] != "usr/bin/curl" {
		t.Errorf("curl-copy matched-base-path = %q, want usr/bin/curl",
			sbom.Components[0].Properties[model.PropertyBasediffMatchedBasePath])
	}
	if sbom.Components[1].Origin != model.OriginApplication {
		t.Errorf("server Origin = %q, want app", sbom.Components[1].Origin)
	}
}

// TestEnrichStampsStrategyPropertyOnNoBase — when no base
// reference can be resolved, the SBOM still gets the strategy
// property so consumers know basediff ran but had nothing to
// compare against.
func TestEnrichStampsStrategyPropertyOnNoBase(t *testing.T) {
	sbom := sampleSBOM()
	img := buildImageWithLayers(t, layerOf("a", "1"))
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if sbom.Metadata.Properties[model.PropertyBasediffStrategy] != "unavailable" {
		t.Errorf("strategy = %q, want unavailable",
			sbom.Metadata.Properties[model.PropertyBasediffStrategy])
	}
}
