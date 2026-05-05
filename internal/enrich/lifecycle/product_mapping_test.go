package lifecycle

import (
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestMapToProduct_ByName(t *testing.T) {
	cases := []struct {
		c        *model.Component
		wantProd string
		wantVer  string
		wantOk   bool
	}{
		{&model.Component{Name: "node", Version: "20.18.0"}, "nodejs", "20", true},
		{&model.Component{Name: "Python", Version: "3.11.5"}, "python", "3.11", true},
		{&model.Component{Name: "python3", Version: "3.12"}, "python", "3.12", true},
		{&model.Component{Name: "go", Version: "1.22.8"}, "go", "1.22", true},
		{&model.Component{Name: "openjdk", Version: "21.0.5"}, "openjdk", "21", true},
		{&model.Component{Name: "java", Version: "17.0.13"}, "openjdk", "17", true},
		{&model.Component{Name: "postgres", Version: "16.4"}, "postgresql", "16", true},
		{&model.Component{Name: "redis", Version: "7.4.1"}, "redis", "7", true},
		{&model.Component{Name: "kubernetes", Version: "1.30.6"}, "kubernetes", "1.30", true},
		{&model.Component{Name: "alpine", Version: "3.20.3"}, "alpine", "3.20", true},
		{&model.Component{Name: "unknown-thing", Version: "1.0"}, "", "", false},
		{&model.Component{Version: "1"}, "", "", false}, // empty Name
		{nil, "", "", false}, // nil Component
	}
	for _, c := range cases {
		name := "<nil>"
		if c.c != nil {
			name = c.c.Name
		}
		t.Run(name, func(t *testing.T) {
			p, v, ok := MapToProduct(c.c)
			if ok != c.wantOk || p != c.wantProd || v != c.wantVer {
				t.Errorf("MapToProduct(%+v) = (%q, %q, %v), want (%q, %q, %v)",
					c.c, p, v, ok, c.wantProd, c.wantVer, c.wantOk)
			}
		})
	}
}

func TestMapToProduct_ByPURLPrefix(t *testing.T) {
	cases := []struct {
		purl     string
		version  string
		wantProd string
		wantVer  string
	}{
		{"pkg:apk/alpine/curl@8.0.1", "3.20.3", "alpine", "3.20"},
		{"pkg:deb/debian/curl@8.0.1?distro=bookworm", "12", "debian", "12"},
		{"pkg:deb/ubuntu/curl@8.0.1", "22.04.5", "ubuntu", "22.04"},
		{"pkg:rpm/centos/curl@8.0.1", "8", "centos", "8"},
		{"pkg:rpm/rocky/bash@5.1", "9", "rocky-linux", "9"},
	}
	for _, c := range cases {
		t.Run(c.purl, func(t *testing.T) {
			p, v, ok := MapToProduct(&model.Component{
				PURL: c.purl, Version: c.version,
			})
			if !ok {
				t.Fatalf("MapToProduct(%q) didn't match", c.purl)
			}
			if p != c.wantProd || v != c.wantVer {
				t.Errorf("got (%q, %q), want (%q, %q)", p, v, c.wantProd, c.wantVer)
			}
		})
	}
}

// TestMapToProduct_PURLBeatsName — when both signals match,
// PURL prefix wins. A `pkg:apk/alpine/...` Component named "alpine"
// routes via the PURL rule (carries the distro version, not the
// individual package version).
func TestMapToProduct_PURLBeatsName(t *testing.T) {
	c := &model.Component{
		Name:    "alpine",
		Version: "3.18.9",
		PURL:    "pkg:apk/alpine/musl@1.2.5",
	}
	p, v, ok := MapToProduct(c)
	if !ok || p != "alpine" {
		t.Errorf("expected alpine product, got %q", p)
	}
	// Version comes from c.Version (the formatVersion helper);
	// since alpine maps as "major.minor", we get "3.18".
	if v != "3.18" {
		t.Errorf("version = %q, want 3.18", v)
	}
}

func TestFormatVersion(t *testing.T) {
	cases := []struct {
		version, format, want string
	}{
		{"", "major", ""},
		{"20.18.0", "major", "20"},
		{"3.11.5", "major.minor", "3.11"},
		{"3", "major.minor", "3"},
		{"1.0", "exact", "1.0"},
		{"7", "major", "7"},
	}
	for _, c := range cases {
		if got := formatVersion(c.version, c.format); got != c.want {
			t.Errorf("formatVersion(%q, %q) = %q, want %q",
				c.version, c.format, got, c.want)
		}
	}
}

// TestProductMappingCount enforces a floor — if a future edit
// drops mapping entries below the popular-products bar, we want
// CI to fail.
func TestProductMappingCount(t *testing.T) {
	purls, names := ProductMappingCount()
	if purls < 8 {
		t.Errorf("PURL prefix mapping count = %d, want >= 8", purls)
	}
	if names < 30 {
		t.Errorf("name mapping count = %d, want >= 30 popular products", names)
	}
}
