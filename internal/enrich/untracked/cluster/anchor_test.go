package cluster

import (
	"strings"
	"testing"
)

// ─── matchAnchor dispatch ──────────────────────────────────────────

func TestMatchAnchorByBasename(t *testing.T) {
	cases := map[string]bool{
		"app/node_modules/lodash/package.json":     true,
		"app/Cargo.toml":                           true,
		"src/go.mod":                               true,
		"build/pom.xml":                            true,
		"src/pyproject.toml":                       true,
		"vendor/composer.json":                     true,
		"chart/Chart.yaml":                         true,
		"site-packages/foo-1.0.dist-info/METADATA": true,
	}
	for p, want := range cases {
		t.Run(p, func(t *testing.T) {
			got := matchAnchor(p) != nil
			if got != want {
				t.Errorf("matchAnchor(%q) found=%v, want %v", p, got, want)
			}
		})
	}
}

func TestMatchAnchorRequiresDistInfoForMETADATA(t *testing.T) {
	// Bare METADATA outside `*.dist-info/` must NOT match.
	if matchAnchor("META-INF/MANIFEST.MF/METADATA") != nil {
		t.Error("METADATA outside dist-info should not be an anchor")
	}
	if matchAnchor("opt/foo/METADATA") != nil {
		t.Error("METADATA outside dist-info should not be an anchor")
	}
}

func TestMatchAnchorBySuffix(t *testing.T) {
	if matchAnchor("vendor/bundle/foo.gemspec") == nil {
		t.Error("*.gemspec should match by suffix")
	}
}

func TestMatchAnchorIgnoresUnknown(t *testing.T) {
	for _, p := range []string{
		"etc/hostname",
		"usr/local/bin/myapp",
		"opt/data/config.yaml",
	} {
		if matchAnchor(p) != nil {
			t.Errorf("matchAnchor(%q) should not match", p)
		}
	}
}

// ─── per-extractor unit tests ──────────────────────────────────────

func TestExtractFromPackageJSON(t *testing.T) {
	body := []byte(`{"name":"lodash","version":"4.17.21","license":"MIT"}`)
	id, err := extractFromPackageJSON("app/node_modules/lodash/package.json", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "lodash" || id.Version != "4.17.21" {
		t.Errorf("identity = %+v", id)
	}
	if id.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("PURL = %q", id.PURL)
	}
	if id.Type != "npm" {
		t.Errorf("Type = %q", id.Type)
	}
}

func TestExtractFromPackageJSONScopedName(t *testing.T) {
	body := []byte(`{"name":"@types/node","version":"20.0.0"}`)
	id, _ := extractFromPackageJSON("p.json", body)
	if id.PURL != "pkg:npm/@types/node@20.0.0" {
		t.Errorf("PURL = %q, want pkg:npm/@types/node@20.0.0", id.PURL)
	}
}

func TestExtractFromPackageJSONEmptyName(t *testing.T) {
	if _, err := extractFromPackageJSON("p.json", []byte(`{"name":""}`)); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestExtractFromPackageJSONMalformed(t *testing.T) {
	if _, err := extractFromPackageJSON("p.json", []byte(`not-json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExtractFromCargoToml(t *testing.T) {
	body := []byte(`
[package]
name = "rocket"
version = "0.5.0"
edition = "2021"

[dependencies]
serde = "1"
`)
	id, err := extractFromCargoToml("crate/Cargo.toml", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "rocket" || id.Version != "0.5.0" {
		t.Errorf("identity = %+v", id)
	}
	if id.PURL != "pkg:cargo/rocket@0.5.0" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromGoMod(t *testing.T) {
	body := []byte("module github.com/example/myservice\n\ngo 1.22\n")
	id, err := extractFromGoMod("svc/go.mod", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "github.com/example/myservice" {
		t.Errorf("Name = %q", id.Name)
	}
	if id.PURL != "pkg:golang/github.com/example/myservice@unknown" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromPomXml(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.2.3</version>
</project>`)
	id, err := extractFromPomXML("svc/pom.xml", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "com.example:app" || id.Version != "1.2.3" {
		t.Errorf("identity = %+v", id)
	}
	if id.PURL != "pkg:maven/com.example/app@1.2.3" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromPomXmlInheritsParent(t *testing.T) {
	body := []byte(`<project>
  <parent>
    <groupId>com.parent</groupId>
    <artifactId>parent-art</artifactId>
    <version>9.0.0</version>
  </parent>
  <artifactId>child</artifactId>
</project>`)
	id, _ := extractFromPomXML("p.xml", body)
	if id.Name != "com.parent:child" {
		t.Errorf("Name = %q, want com.parent:child (inherited groupId)", id.Name)
	}
	if id.Version != "9.0.0" {
		t.Errorf("Version = %q, want 9.0.0 (inherited)", id.Version)
	}
}

func TestExtractFromPyprojectPEP621(t *testing.T) {
	body := []byte(`
[project]
name = "django"
version = "5.0.1"
description = "..."
`)
	id, err := extractFromPyproject("pyproject.toml", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "django" || id.Version != "5.0.1" {
		t.Errorf("identity = %+v", id)
	}
	if id.PURL != "pkg:pypi/django@5.0.1" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromPyprojectPoetry(t *testing.T) {
	body := []byte(`
[tool.poetry]
name = "flask"
version = "3.0.0"
`)
	id, _ := extractFromPyproject("pyproject.toml", body)
	if id.Name != "flask" || id.Version != "3.0.0" {
		t.Errorf("identity = %+v", id)
	}
}

func TestExtractFromPythonMetadata(t *testing.T) {
	body := []byte(`Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: ...

The long description follows here.
`)
	id, err := extractFromPythonMetadata("site-packages/requests-2.31.0.dist-info/METADATA", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "requests" || id.Version != "2.31.0" {
		t.Errorf("identity = %+v", id)
	}
}

func TestExtractFromComposerJSON(t *testing.T) {
	body := []byte(`{"name":"monolog/monolog","version":"3.5.0"}`)
	id, err := extractFromComposerJSON("c.json", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.PURL != "pkg:composer/monolog/monolog@3.5.0" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromComposerJSONNotVendorSlashed(t *testing.T) {
	if _, err := extractFromComposerJSON("c.json", []byte(`{"name":"plain"}`)); err == nil {
		t.Fatal("expected error for non vendor/package name")
	}
}

func TestExtractFromChartYaml(t *testing.T) {
	body := []byte(`
apiVersion: v2
name: nginx
version: 18.1.0
`)
	id, err := extractFromChartYaml("c.yaml", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.PURL != "pkg:helm/nginx@18.1.0" {
		t.Errorf("PURL = %q", id.PURL)
	}
}

func TestExtractFromGemspec(t *testing.T) {
	body := []byte(`Gem::Specification.new do |s|
  s.name        = "rake"
  s.version     = "13.1.0"
  s.summary     = "..."
end`)
	id, err := extractFromGemspec("rake.gemspec", body)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "rake" || id.Version != "13.1.0" {
		t.Errorf("identity = %+v", id)
	}
}

func TestExtractFromGemspecGemVersionWrapper(t *testing.T) {
	body := []byte(`Gem::Specification.new do |s|
  s.name = 'sass'
  s.version = Gem::Version.new('3.7.4')
end`)
	id, _ := extractFromGemspec("sass.gemspec", body)
	if id.Name != "sass" || id.Version != "3.7.4" {
		t.Errorf("identity = %+v", id)
	}
}

func TestExtractFromGemspecNoName(t *testing.T) {
	if _, err := extractFromGemspec("x.gemspec", []byte(`# nothing`)); err == nil {
		t.Fatal("expected error for missing name")
	}
}

// ─── PURL helpers ──────────────────────────────────────────────────

func TestSimplePURLEmptyName(t *testing.T) {
	if got := simplePURL("npm", "", "", "1.0"); got != "" {
		t.Errorf("got %q, want empty for empty name", got)
	}
}

func TestPurlGolangFallsBackToUnknown(t *testing.T) {
	got := purlGolang("github.com/foo/bar", "")
	if !strings.HasSuffix(got, "@unknown") {
		t.Errorf("got %q, want @unknown suffix", got)
	}
}
