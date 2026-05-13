package vex

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleOpenVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2026-001",
  "author": "Security Team",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-12345" },
      "products": [{ "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    },
    {
      "vulnerability": "CVE-2024-67890",
      "products": ["pkg:npm/lodash@4.17.21"],
      "status": "fixed"
    },
    {
      "vulnerability": { "name": "CVE-2024-99999" },
      "products": [{ "@id": "pkg:npm/express@*" }],
      "status": "not_affected"
    },
    {
      "vulnerability": { "name": "CVE-2025-IGNORED" },
      "products": [{ "@id": "pkg:npm/sample@1.0" }],
      "status": "affected"
    }
  ]
}`

const sampleCDXVEX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "vulnerabilities": [
    {
      "id": "CVE-2024-AAA",
      "affects": [{"ref": "pkg:apk/alpine/openssl@3.3.0-r0"}],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_present",
        "detail": "JNDI feature disabled"
      }
    },
    {
      "id": "CVE-2024-BBB",
      "affects": [{"ref": "pkg:apk/alpine/curl@8.6.0-r0"}],
      "analysis": {
        "state": "fixed"
      }
    }
  ]
}`

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		body string
		want Format
	}{
		{"openvex", sampleOpenVEX, FormatOpenVEX},
		{"cdx-vex", sampleCDXVEX, FormatCDXVEX},
		{"empty-object", "{}", FormatUnknown},
		{"non-json", "not json", FormatUnknown},
		{"cdx-sbom-without-vulns", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, FormatUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectFormat([]byte(c.body)); got != c.want {
				t.Errorf("DetectFormat = %v, want %v", got, c.want)
			}
		})
	}
}

func TestFormat_String(t *testing.T) {
	cases := []struct {
		f    Format
		want string
	}{
		{FormatOpenVEX, "openvex"},
		{FormatCDXVEX, "cyclonedx-vex"},
		{FormatUnknown, "unknown"},
	}
	for _, c := range cases {
		if got := c.f.String(); got != c.want {
			t.Errorf("Format(%d).String() = %q, want %q", c.f, got, c.want)
		}
	}
}

func TestLoadStore_OpenVEX(t *testing.T) {
	path := writeTemp(t, "openvex.json", sampleOpenVEX)
	store, err := LoadStore([]string{path})
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	// 4 statements but 1 has status=affected, so 3 effects total.
	if store.Len() != 4 {
		t.Errorf("Len = %d, want 4 (including the affected one — Store keeps it; gate decides on Suppresses)", store.Len())
	}

	// not_affected lookup matches
	eff, ok := store.Lookup("CVE-2024-12345",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if !ok {
		t.Fatal("Lookup CVE-2024-12345 miss")
	}
	if eff.Status != StatusNotAffected {
		t.Errorf("Status = %q, want not_affected", eff.Status)
	}
	if !eff.Suppresses() {
		t.Error("Suppresses() = false on not_affected")
	}
	if eff.Source != path {
		t.Errorf("Source = %q, want %q", eff.Source, path)
	}

	// fixed lookup matches and bare-string vulnerability shape works
	eff, ok = store.Lookup("CVE-2024-67890", "pkg:npm/lodash@4.17.21")
	if !ok {
		t.Fatal("Lookup CVE-2024-67890 miss (bare-string vulnerability shape)")
	}
	if eff.Status != StatusFixed || !eff.Suppresses() {
		t.Errorf("Status = %q, Suppresses = %v, want fixed/true", eff.Status, eff.Suppresses())
	}

	// affected lookup matches but doesn't suppress
	eff, ok = store.Lookup("CVE-2025-IGNORED", "pkg:npm/sample@1.0")
	if !ok {
		t.Fatal("affected statement should still be in Store")
	}
	if eff.Suppresses() {
		t.Error("affected statement Suppresses() = true, want false")
	}
}

func TestLoadStore_CDXVEX(t *testing.T) {
	path := writeTemp(t, "cdx-vex.json", sampleCDXVEX)
	store, err := LoadStore([]string{path})
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if store.Len() != 2 {
		t.Errorf("Len = %d, want 2", store.Len())
	}
	eff, ok := store.Lookup("CVE-2024-AAA", "pkg:apk/alpine/openssl@3.3.0-r0")
	if !ok {
		t.Fatal("openssl lookup miss")
	}
	if eff.Status != StatusNotAffected {
		t.Errorf("Status = %q, want not_affected", eff.Status)
	}
	if eff.Justification != JustVulnerableCodeNotPresent {
		t.Errorf("Justification = %q, want vulnerable_code_not_present (mapped from code_not_present)",
			eff.Justification)
	}
	if eff.Detail != "JNDI feature disabled" {
		t.Errorf("Detail = %q", eff.Detail)
	}
}

func TestLoadStore_UnknownFormat(t *testing.T) {
	path := writeTemp(t, "garbage.json", `{"random":"object"}`)
	_, err := LoadStore([]string{path})
	if err == nil {
		t.Error("expected error on unknown format")
	}
}

func TestLoadStore_FilesMerged(t *testing.T) {
	a := writeTemp(t, "a.json", sampleOpenVEX)
	b := writeTemp(t, "b.json", sampleCDXVEX)
	store, err := LoadStore([]string{a, b})
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if store.Len() != 6 {
		t.Errorf("merged Len = %d, want 6 (4 openvex + 2 cdx)", store.Len())
	}
	srcs := store.Sources()
	if len(srcs) != 2 {
		t.Errorf("Sources = %v, want 2 distinct paths", srcs)
	}
}

func TestPurlsEquivalent(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"pkg:npm/x@1.0", "pkg:npm/x@1.0", true},
		{"pkg:npm/x@1.0", "pkg:npm/y@1.0", false},
		// Wildcard either side
		{"pkg:npm/express@*", "pkg:npm/express@4.18.2", true},
		{"pkg:npm/express@4.18.2", "pkg:npm/express@*", true},
		// Different bases — wildcard doesn't bridge
		{"pkg:npm/foo@*", "pkg:npm/bar@1.0", false},
		// Empty inputs
		{"", "pkg:npm/x@1.0", false},
		{"pkg:npm/x@1.0", "", false},
	}
	for _, c := range cases {
		if got := purlsEquivalent(c.a, c.b); got != c.want {
			t.Errorf("purlsEquivalent(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestStore_LookupWildcard(t *testing.T) {
	path := writeTemp(t, "wildcard.json", sampleOpenVEX)
	store, _ := LoadStore([]string{path})
	// express@* in the VEX must match express@4.18.2
	eff, ok := store.Lookup("CVE-2024-99999", "pkg:npm/express@4.18.2")
	if !ok {
		t.Fatal("wildcard lookup miss — express@* in VEX should match @4.18.2")
	}
	if eff.Status != StatusNotAffected {
		t.Errorf("Status = %q, want not_affected", eff.Status)
	}
}

func TestLoadStore_MissingFile(t *testing.T) {
	_, err := LoadStore([]string{"/does/not/exist.vex"})
	if err == nil {
		t.Error("expected error on missing file")
	}
}

func TestStore_AddEffect_DropsEmptyKeys(t *testing.T) {
	s := NewStore()
	s.AddEffect(Effect{VulnID: "", ProductPURL: "x"})
	s.AddEffect(Effect{VulnID: "CVE-1", ProductPURL: ""})
	s.AddEffect(Effect{VulnID: "CVE-2", ProductPURL: "pkg:npm/y@1"})
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (empty keys dropped)", s.Len())
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
