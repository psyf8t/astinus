package untracked

import (
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestExtractKnownPathsFromComponent_EvidenceLocations(t *testing.T) {
	c := &model.Component{
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{
				{Path: "/app/index.js"},
				{Path: "app/lib.js"},
			},
		},
	}
	got := extractKnownPathsFromComponent(c)
	want := map[string]bool{"app/index.js": true, "app/lib.js": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("missing paths: %v", want)
	}
}

func TestExtractKnownPathsFromComponent_SyftProperties(t *testing.T) {
	c := &model.Component{
		Properties: map[string]string{
			"syft:location:0:path":    "/app/node_modules/lodash/package.json",
			"syft:location:1:path":    "/app/node_modules/lodash/index.js",
			"syft:location:2:layerID": "sha256:deadbeef",
			"syft:package:type":       "npm",
		},
	}
	got := extractKnownPathsFromComponent(c)
	want := map[string]bool{
		"app/node_modules/lodash/package.json": true,
		"app/node_modules/lodash/index.js":     true,
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("missing paths: %v", want)
	}
}

func TestExtractPackageRoot(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"app/node_modules/lodash/package.json", "app/node_modules/lodash"},
		{"usr/lib/python3.11/site-packages/requests/METADATA", "usr/lib/python3.11/site-packages/requests"},
		{"vendor/github.com/foo/bar/go.mod", "vendor/github.com/foo/bar"},
		{"opt/cargo/serde/Cargo.toml", "opt/cargo/serde"},
		{"opt/foo/setup.py", "opt/foo"},
		{"app/node_modules/lodash/index.js", ""}, // not a manifest
		{"random/file.txt", ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := extractPackageRoot(c.path); got != c.want {
				t.Errorf("extractPackageRoot(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestBuildKnownIndex_FromSyftSBOM(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "@colors/colors",
			Properties: map[string]string{
				"syft:location:0:path": "/app/node_modules/@colors/colors/package.json",
			},
		}, {
			Name: "lodash",
			Properties: map[string]string{
				"syft:location:0:path": "/app/node_modules/lodash/package.json",
				"syft:location:1:path": "/app/node_modules/lodash/index.js",
			},
		}},
	}
	idx := buildKnownIndex(sbom)

	// Exact paths.
	for _, p := range []string{
		"app/node_modules/@colors/colors/package.json",
		"app/node_modules/lodash/package.json",
		"app/node_modules/lodash/index.js",
	} {
		if _, ok := idx.paths[p]; !ok {
			t.Errorf("missing path %q in index", p)
		}
	}

	// Package roots inferred from package.json.
	wantDirs := map[string]bool{
		"app/node_modules/@colors/colors/": true,
		"app/node_modules/lodash/":         true,
	}
	for _, d := range idx.dirs {
		if !wantDirs[d] {
			t.Errorf("unexpected dir %q", d)
		}
		delete(wantDirs, d)
	}
	if len(wantDirs) > 0 {
		t.Errorf("missing dirs: %v", wantDirs)
	}
}

func TestIsRedundantAgainstIndex_UnderPackageRoot(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "lodash",
		Properties: map[string]string{
			"syft:location:0:path": "/app/node_modules/lodash/package.json",
		},
	}}}
	idx := buildKnownIndex(sbom)

	cases := []struct {
		path string
		want bool
	}{
		{"app/node_modules/lodash/index.js", true},
		{"app/node_modules/lodash/lib/array.js", true},
		{"app/node_modules/lodash/package.json", true},
		{"app/node_modules/lodash", true},          // exact dir
		{"app/node_modules/other/index.js", false}, // different pkg
		{"opt/foo.bin", false},                     // unrelated
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isRedundantAgainstIndex(c.path, idx); got != c.want {
				t.Errorf("isRedundantAgainstIndex(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestIsDocsOrMetadata(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Filename matches.
		{"opt/foo/LICENSE", true},
		{"opt/foo/README.md", true},
		{"opt/foo/CHANGELOG.txt", true},
		{"opt/foo/COPYING", true},
		{"opt/foo/AUTHORS", true},
		// Extension matches.
		{"opt/foo/header.h", true},
		{"opt/foo/source.cpp", true},
		{"opt/bundle.js.map", true},
		{"opt/types.d.ts", true}, // .ts catches
		{"opt/sig.asc", true},
		// Negatives — these MUST stay (libraries / archives / scripts /
		// real entry points).
		{"opt/foo.so", false},
		{"opt/foo.jar", false},
		{"opt/foo.dll", false},
		{"opt/foo.dylib", false},
		{"opt/foo.py", false}, // entry point — keep
		{"opt/foo.js", false}, // could be minified bundle
		{"opt/bin/yq", false}, // executable, no ext
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isDocsOrMetadata(c.path); got != c.want {
				t.Errorf("isDocsOrMetadata(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestIncludeMaskAllow(t *testing.T) {
	// Default mask: redundant + noise excluded; everything else allowed.
	def := IncludeMask{}
	cases := []struct {
		cat   Category
		allow bool
	}{
		{CategoryExecutable, true},
		{CategoryLibrary, true},
		{CategoryArchive, true},
		{CategoryScript, true},
		{CategoryUnknown, true},
		{CategoryRedundant, false},
		{CategoryNoise, false},
	}
	for _, c := range cases {
		if got := def.allow(c.cat); got != c.allow {
			t.Errorf("default allow(%v) = %v, want %v", c.cat, got, c.allow)
		}
	}

	// IncludeRedundant=true bypasses Redundant only.
	r := IncludeMask{IncludeRedundant: true}
	if !r.allow(CategoryRedundant) {
		t.Error("IncludeRedundant=true should allow Redundant")
	}
	if r.allow(CategoryNoise) {
		t.Error("IncludeRedundant=true should NOT allow Noise")
	}

	// IncludeNoise=true bypasses Noise only.
	n := IncludeMask{IncludeNoise: true}
	if !n.allow(CategoryNoise) {
		t.Error("IncludeNoise=true should allow Noise")
	}
	if n.allow(CategoryRedundant) {
		t.Error("IncludeNoise=true should NOT allow Redundant")
	}
}
