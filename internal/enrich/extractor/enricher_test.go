package extractor

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	fpextractor "github.com/psyf8t/astinus/internal/fingerprint/extractor"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnrichLiftsExistingSubComponentsToTopLevel — the simplest case:
// the untracked enricher previously wrote SubComponents (Go binary
// embedded deps) on a Component. Our enricher must lift them to
// top-level + add RelationshipDependsOn edges. No bundle / image
// involved.
func TestEnrichLiftsExistingSubComponentsToTopLevel(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "tester@1.0",
		Name:   "tester",
		Type:   model.ComponentTypeApplication,
		SubComponents: []model.Component{
			{Name: "github.com/sirupsen/logrus", Version: "v1.9.3",
				PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.3"},
			{Name: "github.com/spf13/cobra", Version: "v1.8.0",
				PURL: "pkg:golang/github.com/spf13/cobra@v1.8.0"},
		},
	}}}

	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	// Existing SubComponents should now be top-level Components.
	hasLogrus, hasCobra := false, false
	for _, c := range sbom.Components {
		switch c.Name {
		case "github.com/sirupsen/logrus":
			hasLogrus = true
		case "github.com/spf13/cobra":
			hasCobra = true
		}
	}
	if !hasLogrus || !hasCobra {
		t.Fatalf("expected logrus + cobra as top-level components; got %v", componentNames(sbom))
	}

	// Parent's SubComponents must be cleared so re-runs don't double-lift.
	if len(sbom.Components[0].SubComponents) != 0 {
		t.Errorf("parent SubComponents not cleared after lift: %v",
			sbom.Components[0].SubComponents)
	}

	// Two depends-on edges must appear from the parent to the new
	// top-level components.
	deps := edgesFrom(sbom, "tester@1.0")
	if len(deps) != 2 {
		t.Errorf("dependency edges from parent = %d, want 2; relationships = %+v",
			len(deps), sbom.Relationships)
	}
}

// TestEnrichDeduplicatesAcrossBinaries — two parent Components both
// list logrus as a SubComponent. After Enrich, logrus must appear as
// a single top-level Component but with TWO depends-on edges (one
// from each parent).
func TestEnrichDeduplicatesAcrossBinaries(t *testing.T) {
	logrusPURL := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	sbom := &model.SBOM{Components: []model.Component{
		{BOMRef: "tool1@1.0", Name: "tool1",
			SubComponents: []model.Component{{
				Name: "github.com/sirupsen/logrus", Version: "v1.9.3", PURL: logrusPURL,
			}}},
		{BOMRef: "tool2@1.0", Name: "tool2",
			SubComponents: []model.Component{{
				Name: "github.com/sirupsen/logrus", Version: "v1.9.3", PURL: logrusPURL,
			}}},
	}}

	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	logrusCount := 0
	for _, c := range sbom.Components {
		if c.Name == "github.com/sirupsen/logrus" {
			logrusCount++
		}
	}
	if logrusCount != 1 {
		t.Errorf("logrus count = %d, want exactly 1 (deduplicated); components = %v",
			logrusCount, componentNames(sbom))
	}

	logrusEdges := 0
	for _, r := range sbom.Relationships {
		if r.TargetRef == logrusPURL && r.Type == model.RelationshipDependsOn {
			logrusEdges++
		}
	}
	if logrusEdges != 2 {
		t.Errorf("edges to logrus = %d, want 2 (one per parent); rels = %+v",
			logrusEdges, sbom.Relationships)
	}
}

// TestEnrichReusesExistingTopLevelComponent — a dep that already
// exists as a top-level Component (the input SBOM had it) must NOT
// be duplicated; the parent should get a RelationshipDependsOn edge
// to the existing BOMRef.
func TestEnrichReusesExistingTopLevelComponent(t *testing.T) {
	logrusPURL := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	sbom := &model.SBOM{Components: []model.Component{
		{BOMRef: "preexisting-logrus", Name: "github.com/sirupsen/logrus",
			Version: "v1.9.3", PURL: logrusPURL, Type: model.ComponentTypeLibrary},
		{BOMRef: "tester@1.0", Name: "tester",
			SubComponents: []model.Component{{
				Name: "github.com/sirupsen/logrus", Version: "v1.9.3", PURL: logrusPURL,
			}}},
	}}

	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	logrusCount := 0
	for _, c := range sbom.Components {
		if c.PURL == logrusPURL {
			logrusCount++
		}
	}
	if logrusCount != 1 {
		t.Errorf("logrus count = %d, want 1 (no duplicate)", logrusCount)
	}
	// Edge should target the PRE-EXISTING bomref, not a new synthesised one.
	found := false
	for _, r := range sbom.Relationships {
		if r.SourceRef == "tester@1.0" && r.TargetRef == "preexisting-logrus" {
			found = true
		}
	}
	if !found {
		t.Errorf("edge to preexisting-logrus missing; rels = %+v", sbom.Relationships)
	}
}

// TestEnrichWalksImageAndExtractsGoBinary — the canonical end-to-end
// test: build a real Go binary, embed it in an in-memory v1.Image,
// add a Component pointing at the binary's path, run the enricher.
// Expect the binary's embedded deps as top-level Components + edges.
//
// Skipped on non-{linux,darwin} where the test scaffold's `go build`
// of a multi-package program is fragile across CI runners.
func TestEnrichWalksImageAndExtractsGoBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("requires `go build`; skipped in -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("test scaffold builds an ELF; skipped on windows")
	}

	binPath, depImports := buildGoBinaryWithDeps(t)
	binBody, err := os.ReadFile(binPath) //nolint:gosec
	if err != nil {
		t.Fatalf("read built binary: %v", err)
	}

	const inImagePath = "usr/local/bin/tester"
	img := buildImage(t, map[string][]byte{inImagePath: binBody})

	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "tester@1.0",
		Name:   "tester",
		Type:   model.ComponentTypeApplication,
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "/" + inImagePath}},
		},
	}}}
	bundle := image.NewBundle(name.MustParseReference("test:latest"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	for _, want := range depImports {
		found := false
		for _, c := range sbom.Components {
			if strings.HasPrefix(c.PURL, "pkg:golang/"+want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected extracted dep %q not found; components = %v",
				want, componentNames(sbom))
		}
	}

	// At least one depends-on edge from tester to a lifted component.
	edges := edgesFrom(sbom, "tester@1.0")
	if len(edges) == 0 {
		t.Errorf("no depends-on edges from tester; rels = %+v", sbom.Relationships)
	}
}

// TestEnrichIdempotent — running the enricher twice on the same SBOM
// must not double-add components or edges. The lift phase clears
// SubComponents after promoting them, so the second run sees an
// empty slate and is a no-op.
func TestEnrichIdempotent(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "tester@1.0", Name: "tester",
		SubComponents: []model.Component{{
			Name: "github.com/sirupsen/logrus", Version: "v1.9.3",
			PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
		}},
	}}}

	e := New()
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("first Enrich: %v", err)
	}
	firstComps := len(sbom.Components)
	firstRels := len(sbom.Relationships)

	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("second Enrich: %v", err)
	}
	if len(sbom.Components) != firstComps {
		t.Errorf("components changed on re-run: %d → %d", firstComps, len(sbom.Components))
	}
	if len(sbom.Relationships) != firstRels {
		t.Errorf("relationships changed on re-run: %d → %d", firstRels, len(sbom.Relationships))
	}
}

func TestEnrichNilSBOM(t *testing.T) {
	if err := New().Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestEnricher_NameAndDependencies(t *testing.T) {
	e := New()
	if e.Name() != Name {
		t.Errorf("Name = %q, want %q", e.Name(), Name)
	}
	deps := e.Dependencies()
	if len(deps) != 1 || deps[0] != "untracked" {
		t.Errorf("Dependencies = %v, want [untracked]", deps)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"/usr/local/bin/yq":   "usr/local/bin/yq",
		"usr/local/bin/yq":    "usr/local/bin/yq",
		"/usr/./local/bin/yq": "usr/local/bin/yq",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSynthBOMRefFallbacks(t *testing.T) {
	// PURL preferred.
	if got := synthBOMRef(&model.Component{PURL: "pkg:npm/x@1"}); got != "pkg:npm/x@1" {
		t.Errorf("got %q", got)
	}
	// name@version fallback.
	if got := synthBOMRef(&model.Component{Name: "thing", Version: "1.0"}); got != "thing@1.0" {
		t.Errorf("got %q", got)
	}
	// missing version → @unknown.
	if got := synthBOMRef(&model.Component{Name: "thing"}); got != "thing@unknown" {
		t.Errorf("got %q", got)
	}
	// total fallback to sha-prefixed identifier (rare).
	if got := synthBOMRef(&model.Component{}); !strings.HasPrefix(got, "extracted-") {
		t.Errorf("got %q, want extracted-* fallback", got)
	}
	if synthBOMRef(nil) != "" {
		t.Error("nil component should return empty BOMRef")
	}
}

func TestAttachExtractedDeps_SkipsDuplicatesByPURL(t *testing.T) {
	purl := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	c := &model.Component{
		Name: "tester",
		SubComponents: []model.Component{{
			Name: "github.com/sirupsen/logrus", PURL: purl,
		}},
	}
	id := fpextractor.Identity{
		Source: "go",
		SubComponents: []fpextractor.Identity{
			{Name: "github.com/sirupsen/logrus", PURL: purl, Version: "v1.9.3"},
			{Name: "github.com/spf13/cobra",
				PURL: "pkg:golang/github.com/spf13/cobra@v1.8.0", Version: "v1.8.0"},
		},
	}
	attachExtractedDeps(c, id)
	if len(c.SubComponents) != 2 {
		t.Errorf("SubComponents = %d, want 2 (logrus dedup + cobra appended)", len(c.SubComponents))
	}
	if c.Properties["astinus:extractor:source"] != "go" {
		t.Errorf("source stamp not written: %v", c.Properties)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────

func componentNames(sbom *model.SBOM) []string {
	out := make([]string, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		out = append(out, c.Name)
	}
	return out
}

func edgesFrom(sbom *model.SBOM, src string) []model.Relationship {
	var out []model.Relationship
	for _, r := range sbom.Relationships {
		if r.SourceRef == src {
			out = append(out, r)
		}
	}
	return out
}

func buildGoBinaryWithDeps(t *testing.T) (string, []string) {
	t.Helper()
	tdir := t.TempDir()
	mustWrite := func(rel, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tdir, rel), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	// A minimal program importing two third-party deps so BuildInfo
	// records them. We don't need the program to do anything useful;
	// the imports drive the dependency graph.
	mustWrite("go.mod", `module example.com/test

go 1.22

require (
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
)
`)
	mustWrite("main.go", `package main

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	c := &cobra.Command{Use: "tester"}
	logrus.Info(c.Use)
}
`)
	out := filepath.Join(tdir, "tester")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tidy := exec.CommandContext(ctx, "go", "mod", "tidy")
	tidy.Dir = tdir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if outBytes, err := tidy.CombinedOutput(); err != nil {
		t.Skipf("`go mod tidy` failed (network?): %v\n%s", err, outBytes)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", out, ".")
	build.Dir = tdir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if outBytes, err := build.CombinedOutput(); err != nil {
		t.Skipf("`go build` failed: %v\n%s", err, outBytes)
	}
	return out, []string{
		"github.com/sirupsen/logrus",
		"github.com/spf13/cobra",
	}
}

// buildImage assembles an in-memory v1.Image whose single layer holds
// the supplied paths. Mirrors the helper in internal/enrich/untracked.
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
		hdr := &tar.Header{
			Name:     path,
			Mode:     0o755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
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
