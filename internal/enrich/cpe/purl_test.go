package cpe

import "testing"

func TestParsePURLBasic(t *testing.T) {
	cases := map[string]PURL{
		"pkg:npm/express@4.18.2": {Type: "npm", Name: "express", Version: "4.18.2"},
		"pkg:pypi/django@4.2":    {Type: "pypi", Name: "django", Version: "4.2"},
		"pkg:gem/rails@7.1.0":    {Type: "gem", Name: "rails", Version: "7.1.0"},
		"pkg:cargo/serde@1.0":    {Type: "cargo", Name: "serde", Version: "1.0"},
	}
	for in, want := range cases {
		got, err := ParsePURL(in)
		if err != nil {
			t.Fatalf("ParsePURL(%q): %v", in, err)
		}
		if got.Type != want.Type || got.Name != want.Name || got.Version != want.Version {
			t.Errorf("ParsePURL(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestParsePURLNamespace(t *testing.T) {
	got, err := ParsePURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if got.Type != "maven" {
		t.Errorf("Type = %q", got.Type)
	}
	if got.Namespace != "org.apache.logging.log4j" {
		t.Errorf("Namespace = %q", got.Namespace)
	}
	if got.Name != "log4j-core" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.Version != "2.17.1" {
		t.Errorf("Version = %q", got.Version)
	}
}

func TestParsePURLNamespaceMultiSegment(t *testing.T) {
	got, _ := ParsePURL("pkg:golang/github.com/spf13/cobra@v1.10.2")
	if got.Namespace != "github.com/spf13" || got.Name != "cobra" {
		t.Errorf("got %+v", got)
	}
}

func TestParsePURLNoVersion(t *testing.T) {
	got, err := ParsePURL("pkg:apk/alpine/openssl")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if got.Version != "" {
		t.Errorf("Version = %q, want empty", got.Version)
	}
	if got.Namespace != "alpine" || got.Name != "openssl" {
		t.Errorf("got %+v", got)
	}
}

func TestParsePURLQualifiers(t *testing.T) {
	got, err := ParsePURL("pkg:deb/debian/curl@7.88.1?arch=amd64&distro=debian-12")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if got.Qualifiers["arch"] != "amd64" {
		t.Errorf("arch = %q", got.Qualifiers["arch"])
	}
	if got.Qualifiers["distro"] != "debian-12" {
		t.Errorf("distro = %q", got.Qualifiers["distro"])
	}
}

func TestParsePURLSubpath(t *testing.T) {
	got, err := ParsePURL("pkg:generic/hello@1.0#bin/hello")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if got.Subpath != "bin/hello" {
		t.Errorf("Subpath = %q", got.Subpath)
	}
}

func TestParsePURLPercentDecoded(t *testing.T) {
	got, err := ParsePURL("pkg:nuget/Microsoft.AspNetCore.App@8.0.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if got.Name != "Microsoft.AspNetCore.App" {
		t.Errorf("Name = %q", got.Name)
	}
}

func TestParsePURLErrors(t *testing.T) {
	for _, bad := range []string{"", "express", "pkg:npm", "pkg:npm/"} {
		if _, err := ParsePURL(bad); err == nil {
			t.Errorf("ParsePURL(%q) should error", bad)
		}
	}
}

func TestPURLString(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/express@4.18.2":                               "pkg:npm/express@4.18.2",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
	}
	for in, want := range cases {
		got, _ := ParsePURL(in)
		if got.String() != want {
			t.Errorf("round-trip: in=%q out=%q", in, got.String())
		}
	}
}
