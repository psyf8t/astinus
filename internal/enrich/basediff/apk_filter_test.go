package basediff

import (
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestPathsForComponent_FiltersApkDBForApkRows — S6 Task 2: for an
// apk-managed component (`pkg:apk/...` PURL), the
// `/lib/apk/db/installed` path is metadata about the package
// manager, not about the artifact. Including it in the path set
// causes the content strategy to mark every apk row as
// `OriginBaseImage` because the DB path lives in BOTH the base
// alpine image AND every layer that ran `apk add`. ADR-0059.
func TestPathsForComponent_FiltersApkDBForApkRows(t *testing.T) {
	c := &model.Component{
		Name: "curl",
		PURL: "pkg:apk/alpine/curl@8.5.0-r0",
		Properties: map[string]string{
			"syft:location:0:path": "/lib/apk/db/installed",
			"syft:location:1:path": "/usr/bin/curl",
		},
	}
	paths := pathsForComponent(c)
	for _, p := range paths {
		if p == "/lib/apk/db/installed" {
			t.Errorf("apk DB path leaked through for apk component; paths = %v", paths)
		}
	}
	// The actual binary path MUST survive — that's the one the
	// content strategy uses to classify base-vs-app.
	hasBinary := false
	for _, p := range paths {
		if p == "/usr/bin/curl" {
			hasBinary = true
		}
	}
	if !hasBinary {
		t.Errorf("/usr/bin/curl filtered out alongside apk DB; paths = %v", paths)
	}
}

// TestPathsForComponent_KeepsApkDBForNonApkRows — guards the
// narrow scope of the filter. A `pkg:generic/...` or
// `pkg:deb/...` component that happens to evidence
// `/lib/apk/db/installed` (e.g. a layer-mounting tool that
// catalogues mounted alpine images) keeps the path. The filter is
// keyed on the PURL prefix, not the path. S6 Task 2.
func TestPathsForComponent_KeepsApkDBForNonApkRows(t *testing.T) {
	c := &model.Component{
		Name: "non-apk-with-apk-db-evidence",
		PURL: "pkg:generic/alpine-cataloguer@1.0",
		Properties: map[string]string{
			"syft:location:0:path": "/lib/apk/db/installed",
		},
	}
	paths := pathsForComponent(c)
	if len(paths) != 1 || paths[0] != "/lib/apk/db/installed" {
		t.Errorf("non-apk paths = %v, want [/lib/apk/db/installed] preserved", paths)
	}
}

// TestFilterApkMetadataPaths_NilComponent guards the helper from
// the empty-component edge case. Should not panic.
func TestFilterApkMetadataPaths_NilComponent(t *testing.T) {
	got := filterApkMetadataPaths(nil, []string{"/lib/apk/db/installed"})
	if len(got) != 1 {
		t.Errorf("nil component: filter dropped paths (%v) — should be no-op", got)
	}
}
