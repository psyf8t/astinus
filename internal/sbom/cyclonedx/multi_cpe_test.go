package cyclonedx

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestComponentFromCDX_PreservesMultiSyftCPE23 — S6 Task 5
// regression gate. Syft emits multiple `syft:cpe23` properties for
// multi-product packages (busybox-applet ssl_client → busybox /
// ssl_client / ssl-client variants). Pre-S6 propsFromCDX collapsed
// to a single value because `model.Component.Properties` is a
// single-value map; the resolver chain then saw only one
// candidate and Grype lost the CVE match. componentFromCDX must
// harvest every `syft:cpe23` entry into `c.CPEs` BEFORE
// propsFromCDX collapses. ADR-0062.
func TestComponentFromCDX_PreservesMultiSyftCPE23(t *testing.T) {
	primary := "cpe:2.3:a:ssl_client:ssl_client:1.37.0-r30:*:*:*:*:*:*:*"
	in := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       "ssl_client",
		Version:    "1.37.0-r30",
		PackageURL: "pkg:apk/alpine/ssl_client@1.37.0-r30",
		CPE:        primary,
		Properties: &[]cdx.Property{
			{Name: "syft:cpe23", Value: "cpe:2.3:a:busybox:busybox:1.37.0-r30:*:*:*:*:*:*:*"},
			{Name: "syft:cpe23", Value: "cpe:2.3:a:busybox:ssl_client:1.37.0-r30:*:*:*:*:*:*:*"},
			{Name: "syft:cpe23", Value: "cpe:2.3:a:busybox:ssl-client:1.37.0-r30:*:*:*:*:*:*:*"},
			{Name: "syft:cpe23", Value: "cpe:2.3:a:ssl_client:ssl_client:1.37.0-r30:*:*:*:*:*:*:*"},
			{Name: "syft:cpe23", Value: "cpe:2.3:a:ssl-client:ssl-client:1.37.0-r30:*:*:*:*:*:*:*"},
			{Name: "syft:package:type", Value: "apk"},
		},
	}
	out := componentFromCDX(in)

	// c.CPEs must carry the primary plus 4 unique syft:cpe23
	// candidates (5th syft entry duplicates the primary —
	// `ssl_client:ssl_client` is what `c.CPE` carries).
	if len(out.CPEs) < 5 {
		t.Errorf("c.CPEs = %v, want at least 5 entries (primary + 4 syft alts)", out.CPEs)
	}
	wantContains := []string{
		"busybox:busybox",
		"busybox:ssl_client",
		"busybox:ssl-client",
		"ssl-client:ssl-client",
	}
	for _, want := range wantContains {
		found := false
		for _, c := range out.CPEs {
			if strings.Contains(c, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("c.CPEs missing %q variant; got %v", want, out.CPEs)
		}
	}
}

// TestComponentFromCDX_NoSyftCPEsLeavesEmpty asserts the multi-CPE
// harvest is a no-op on components without `syft:cpe23` properties.
// S6 Task 5.
func TestComponentFromCDX_NoSyftCPEsLeavesEmpty(t *testing.T) {
	in := cdx.Component{
		Type: cdx.ComponentTypeLibrary,
		Name: "boring-package",
		Properties: &[]cdx.Property{
			{Name: "syft:package:type", Value: "npm"},
		},
	}
	out := componentFromCDX(in)
	if len(out.CPEs) != 0 {
		t.Errorf("c.CPEs = %v on no-CPE input, want empty", out.CPEs)
	}
}

// TestComponentFromCDX_HydrateAstinusFields_OnlyNumericExtraCPE —
// S6 Task 5 fixes the overbroad pre-S6 sweep that grabbed every
// `astinus:cpe:*` property as a CPE (including
// `astinus:cpe:source`, `:confidence`, `:alternative:1:source`,
// etc.). The post-fix sweep accepts only the numeric `:N` shape
// the writer produces for extra CPEs. ADR-0062.
func TestComponentFromCDX_HydrateAstinusFields_OnlyNumericExtraCPE(t *testing.T) {
	extraCPE := "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"
	in := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "x",
		Version: "1.0",
		CPE:     "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Properties: &[]cdx.Property{
			// Numeric extra CPE — must be hydrated into c.CPEs.
			{Name: "astinus:cpe:1", Value: extraCPE},
			// Metadata properties that share the prefix — must
			// stay in c.Properties, NOT swept into c.CPEs.
			{Name: "astinus:cpe:source", Value: "nvd-api"},
			{Name: "astinus:cpe:confidence", Value: "0.95"},
			{Name: "astinus:cpe:scope", Value: "evidence-only"},
			{Name: "astinus:cpe:rationale", Value: "go-module evidence-only"},
		},
	}
	out := componentFromCDX(in)

	if len(out.CPEs) != 2 {
		t.Errorf("c.CPEs = %v, want 2 (primary + numeric extra)", out.CPEs)
	}
	for _, c := range out.CPEs {
		if c == "nvd-api" || c == "0.95" || c == "evidence-only" {
			t.Errorf("metadata property leaked into c.CPEs as %q", c)
		}
	}
	for _, key := range []string{
		"astinus:cpe:source",
		"astinus:cpe:confidence",
		"astinus:cpe:scope",
		"astinus:cpe:rationale",
	} {
		if _, ok := out.Properties[key]; !ok {
			t.Errorf("metadata property %q lost from c.Properties", key)
		}
	}
}

// TestIsNumericExtraCPEKey pins the helper's contract. ADR-0062.
func TestIsNumericExtraCPEKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"astinus:cpe:1", true},
		{"astinus:cpe:42", true},
		{"astinus:cpe:0", true},
		{"astinus:cpe:source", false},
		{"astinus:cpe:confidence", false},
		{"astinus:cpe:alternative:1", false},
		{"astinus:cpe:alternative:1:source", false},
		{"astinus:cpe:", false},
		{"astinus:cpe:1a", false},
		{"other:cpe:1", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isNumericExtraCPEKey(c.key); got != c.want {
			t.Errorf("isNumericExtraCPEKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}
