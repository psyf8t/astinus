package attribution

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestDebEarliest_OverridesSyftLocation drives a 3-layer image
// where /var/lib/dpkg/status grows across layers (debian base +
// apt-get install libpq + apt-get install postgresql-17). Syft
// would stamp every deb row at the DB path (which lives in the
// LAST layer because each apt-get rewrites the status file),
// and the default stamper would pin every deb component to the
// last apt-touching layer. The deb-earliest override must move
// each row to its actual introduction layer. ADR-0060 amendment.
func TestDebEarliest_OverridesSyftLocation(t *testing.T) {
	layer0 := "Package: libc6\nVersion: 2.41-12+deb13u2\n\nPackage: bash\nVersion: 5.2.21-2\n"
	layer1 := layer0 + "\nPackage: libpq5\nVersion: 17.0-1\n"
	layer2 := layer1 + "\nPackage: postgresql-17\nVersion: 17.0-1\n"

	img := buildImage(t, []map[string]string{
		{layer.DpkgStatusPath: layer0},
		{layer.DpkgStatusPath: layer1},
		{layer.DpkgStatusPath: layer2},
	})

	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef:  "comp-libc6",
				Name:    "libc6",
				Version: "2.41-12+deb13u2",
				PURL:    "pkg:deb/debian/libc6@2.41-12+deb13u2",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.DpkgStatusPath,
				},
			},
			{
				BOMRef:  "comp-libpq5",
				Name:    "libpq5",
				Version: "17.0-1",
				PURL:    "pkg:deb/debian/libpq5@17.0-1",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.DpkgStatusPath,
				},
			},
			{
				BOMRef:  "comp-postgresql",
				Name:    "postgresql-17",
				Version: "17.0-1",
				PURL:    "pkg:deb/debian/postgresql-17@17.0-1",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.DpkgStatusPath,
				},
			},
			// Non-deb row — must NOT be touched by the override.
			{
				BOMRef:  "comp-myapp",
				Name:    "myapp",
				Version: "1.0",
				PURL:    "pkg:generic/myapp@1.0",
			},
		},
	}
	bundle := image.NewBundle(mustTag(t, "test/debian:1"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	cases := []struct {
		name string
		idx  int
	}{
		{"libc6", 0},
		{"libpq5", 1},
		{"postgresql-17", 2},
	}
	for _, c := range cases {
		comp := findByName(sbom, c.name)
		if comp == nil {
			t.Fatalf("%s missing from output", c.name)
		}
		if comp.LayerInfo == nil {
			t.Fatalf("%s LayerInfo nil — deb-earliest did not run", c.name)
		}
		if comp.LayerInfo.LayerIndex != c.idx {
			t.Errorf("%s LayerIndex = %d, want %d (deb-earliest override)",
				c.name, comp.LayerInfo.LayerIndex, c.idx)
		}
		if got := comp.Properties[model.PropertyLayerSource]; got != "deb-earliest-layer" {
			t.Errorf("%s astinus:layer:source = %q, want deb-earliest-layer",
				c.name, got)
		}
	}

	app := findByName(sbom, "myapp")
	if app == nil {
		t.Fatal("non-deb component myapp missing from output")
	}
	if app.Properties[model.PropertyLayerSource] == "deb-earliest-layer" {
		t.Error("non-deb component stamped with deb-earliest-layer — override widened past pkg:deb/")
	}
}

// TestDebEarliest_LeavesUnknownDebRowsAlone asserts the override
// is a no-op for deb rows whose (name, version) isn't in the
// FileMap's dpkg-earliest index. Existing stamps (filemap-
// last-touch / syft-location-property) survive.
func TestDebEarliest_LeavesUnknownDebRowsAlone(t *testing.T) {
	layer0 := "Package: libc6\nVersion: 2.41-12+deb13u2\n"
	img := buildImage(t, []map[string]string{
		{
			layer.DpkgStatusPath:  layer0,
			"usr/bin/some-binary": "elf",
		},
	})

	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "comp-mystery",
			Name:    "mystery-pkg",
			Version: "9.9.9",
			PURL:    "pkg:deb/debian/mystery-pkg@9.9.9",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{
					{Path: "/usr/bin/some-binary"},
				},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/debian:2"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	comp := findByName(sbom, "mystery-pkg")
	if comp == nil {
		t.Fatal("mystery-pkg missing")
	}
	if comp.LayerInfo == nil {
		t.Fatal("mystery-pkg LayerInfo nil — filemap-last-touch must have stamped via Evidence.Locations")
	}
	if got := comp.Properties[model.PropertyLayerSource]; got != "filemap-last-touch" {
		t.Errorf("astinus:layer:source = %q, want filemap-last-touch (deb-earliest had nothing to override with)",
			got)
	}
}

// TestIsDebComponent — PURL prefix check.
func TestIsDebComponent(t *testing.T) {
	cases := []struct {
		purl string
		want bool
	}{
		{"pkg:deb/debian/libc6@2.41", true},
		{"pkg:deb/ubuntu/libc6@2.41", true},
		{"pkg:apk/alpine/musl@1.2.5-r0", false},
		{"pkg:npm/express@4.18.2", false},
		{"", false},
	}
	for _, c := range cases {
		comp := &model.Component{PURL: c.purl}
		if got := isDebComponent(comp); got != c.want {
			t.Errorf("isDebComponent(%q) = %v, want %v", c.purl, got, c.want)
		}
	}
	if isDebComponent(nil) {
		t.Errorf("isDebComponent(nil) = true, want false")
	}
}
