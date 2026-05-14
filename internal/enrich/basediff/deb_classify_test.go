package basediff

import (
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestClassifyByLayerIndex_DebFallback — Sprint 7 Task 3. The
// fallback now handles deb in addition to apk. Layer 0 → base;
// > 0 → application. Source must be `deb-earliest-layer` (not
// `apk-earliest-layer` or any other). ADR-0060 amendment.
func TestClassifyByLayerIndex_DebFallback(t *testing.T) {
	cases := []struct {
		name      string
		purl      string
		source    string
		idx       int
		wantOrig  model.Origin
		wantMatch bool
	}{
		{
			"deb layer 0 → base",
			"pkg:deb/debian/libc6@2.41-12+deb13u2",
			"deb-earliest-layer",
			0, model.OriginBaseImage, true,
		},
		{
			"deb layer 2 → application",
			"pkg:deb/debian/postgresql-17@17.0-1",
			"deb-earliest-layer",
			2, model.OriginApplication, true,
		},
		{
			"deb without deb-earliest source — skipped",
			"pkg:deb/debian/libc6@2.41",
			"filemap-last-touch",
			0, "", false,
		},
		{
			"deb with apk-earliest source mismatch — skipped",
			"pkg:deb/debian/libc6@2.41",
			"apk-earliest-layer",
			0, "", false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comp := &model.Component{
				PURL: c.purl,
				Properties: map[string]string{
					model.PropertyLayerSource: c.source,
				},
				LayerInfo: &model.LayerInfo{LayerIndex: c.idx},
			}
			got, ok := classifyApkByLayerIndex(comp)
			if ok != c.wantMatch {
				t.Errorf("ok = %v, want %v", ok, c.wantMatch)
			}
			if got != c.wantOrig {
				t.Errorf("Origin = %v, want %v", got, c.wantOrig)
			}
		})
	}
}

// TestFilterApkMetadataPaths_DropsDpkgStatusForDeb — the filter
// now strips /var/lib/dpkg/status for deb components alongside
// the apk DB path for apk components. S7 Task 3.
func TestFilterApkMetadataPaths_DropsDpkgStatusForDeb(t *testing.T) {
	c := &model.Component{
		Name: "libc6",
		PURL: "pkg:deb/debian/libc6@2.41",
		Properties: map[string]string{
			"syft:location:0:path": "/var/lib/dpkg/status",
			"syft:location:1:path": "/usr/lib/x86_64-linux-gnu/libc.so.6",
		},
	}
	paths := pathsForComponent(c)
	for _, p := range paths {
		if p == "/var/lib/dpkg/status" {
			t.Errorf("dpkg status path leaked through for deb component; paths = %v", paths)
		}
	}
	hasBinary := false
	for _, p := range paths {
		if p == "/usr/lib/x86_64-linux-gnu/libc.so.6" {
			hasBinary = true
		}
	}
	if !hasBinary {
		t.Errorf("libc.so.6 path filtered alongside dpkg-status; paths = %v", paths)
	}
}

// TestFilterApkMetadataPaths_KeepsDpkgStatusForNonDeb — guards
// the narrow scope. A non-deb component that happens to reference
// /var/lib/dpkg/status (e.g. a Debian-cataloguer tool) keeps the
// path. S7 Task 3.
func TestFilterApkMetadataPaths_KeepsDpkgStatusForNonDeb(t *testing.T) {
	c := &model.Component{
		Name: "non-deb-cataloguer",
		PURL: "pkg:generic/debian-cataloguer@1.0",
		Properties: map[string]string{
			"syft:location:0:path": "/var/lib/dpkg/status",
		},
	}
	paths := pathsForComponent(c)
	if len(paths) != 1 || paths[0] != "/var/lib/dpkg/status" {
		t.Errorf("non-deb paths = %v, want [/var/lib/dpkg/status] preserved", paths)
	}
}
