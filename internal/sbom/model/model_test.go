package model

import "testing"

func TestFormatPredicates(t *testing.T) {
	cases := []struct {
		f      Format
		isCDX  bool
		isSPDX bool
	}{
		{FormatCycloneDXJSON, true, false},
		{FormatCycloneDXXML, true, false},
		{FormatSPDXJSON, false, true},
		{FormatSPDXTagValue, false, true},
		{FormatUnknown, false, false},
	}
	for _, c := range cases {
		if got := c.f.IsCycloneDX(); got != c.isCDX {
			t.Errorf("Format(%s).IsCycloneDX() = %v, want %v", c.f, got, c.isCDX)
		}
		if got := c.f.IsSPDX(); got != c.isSPDX {
			t.Errorf("Format(%s).IsSPDX() = %v, want %v", c.f, got, c.isSPDX)
		}
	}
}

func TestNormalizeHashAlgorithm(t *testing.T) {
	cases := map[string]string{
		"SHA-256":     HashAlgorithmSHA256,
		"sha256":      HashAlgorithmSHA256,
		"SHA_256":     HashAlgorithmSHA256,
		"sha-1":       HashAlgorithmSHA1,
		"SHA-512":     HashAlgorithmSHA512,
		"BLAKE2b-256": HashAlgorithmBlake2b256,
		"blake2b256":  HashAlgorithmBlake2b256,
		"BLAKE2b-512": HashAlgorithmBlake2b512,
		"SHA-384":     HashAlgorithmSHA384,
		"":            "",
		"weird-thing": "weirdthing",
		"swhid":       HashAlgorithmSWHID,
		"MD5":         HashAlgorithmMD5,
	}
	for in, want := range cases {
		if got := NormalizeHashAlgorithm(in); got != want {
			t.Errorf("NormalizeHashAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOriginIsKnown(t *testing.T) {
	for _, o := range []Origin{OriginBaseImage, OriginApplication, OriginUnknown} {
		if !o.IsKnown() {
			t.Errorf("Origin(%q) should be known", o)
		}
	}
	if Origin("rogue").IsKnown() {
		t.Error("rogue origin should not be known")
	}
	if Origin("").IsKnown() {
		t.Error("empty origin should not be known")
	}
}

func TestLicenseHelpers(t *testing.T) {
	if (License{}).IsEmpty() != true {
		t.Error("zero license should be empty")
	}
	if (License{SPDXID: "MIT"}).IsEmpty() {
		t.Error("license with SPDXID should not be empty")
	}
	if !(License{Expression: "MIT OR Apache-2.0"}).IsExpression() {
		t.Error("expression-only license should report IsExpression")
	}
	if (License{SPDXID: "MIT"}).IsExpression() {
		t.Error("structured license should not report IsExpression")
	}
}

func TestEvidenceIsZero(t *testing.T) {
	if !(Evidence{}).IsZero() {
		t.Error("zero evidence must be IsZero")
	}
	if (Evidence{Method: "fingerprint"}).IsZero() {
		t.Error("evidence with method must not be IsZero")
	}
	if (Evidence{Confidence: 0.5}).IsZero() {
		t.Error("evidence with confidence must not be IsZero")
	}
	if (Evidence{Locations: []EvidenceLocation{{Path: "/a", LineNo: 1}}}).IsZero() {
		t.Error("evidence with locations must not be IsZero")
	}
}

func TestComponentTypeValues(t *testing.T) {
	// Spot-check the canonical strings; a typo here would silently
	// break round-trip tests later, so we keep an explicit assertion.
	want := map[ComponentType]string{
		ComponentTypeApplication: "application",
		ComponentTypeContainer:   "container",
		ComponentTypeFile:        "file",
		ComponentTypeLibrary:     "library",
		ComponentTypeOS:          "operating-system",
		ComponentTypeUnknown:     "unknown",
	}
	for ct, s := range want {
		if string(ct) != s {
			t.Errorf("ComponentType %v string = %q, want %q", ct, string(ct), s)
		}
	}
}

func TestPropertyNamespaceConsistency(t *testing.T) {
	// Every astinus property must live under PropertyNamespace.
	all := []string{
		PropertyOrigin,
		PropertyLayerDigest,
		PropertyLayerIndex,
		PropertyLayerDockerfileLine,
		PropertyLayerAddedBy,
		PropertyEvidenceMethod,
		PropertyEvidenceConfidence,
		PropertyEnrichedBy,
		PropertyEnrichedVersion,
	}
	for _, p := range all {
		if len(p) <= len(PropertyNamespace)+1 || p[:len(PropertyNamespace)+1] != PropertyNamespace+":" {
			t.Errorf("property %q is not under namespace %q", p, PropertyNamespace)
		}
	}
}

// TestDetectSource — S4 Task 5: tools-string matching for the
// upstream SBOM source. Matches case-insensitively on Tool.Name and
// Tool.Vendor so the helper recognises both
// `Tool{Name:"syft"}` and `Tool{Vendor:"anchore", Name:"syft"}`.
func TestDetectSource(t *testing.T) {
	cases := []struct {
		name  string
		tools []Tool
		want  Source
	}{
		{name: "nil sbom is unknown", tools: nil, want: SourceUnknown},
		{name: "no tools is unknown", tools: []Tool{}, want: SourceUnknown},
		{name: "syft bare", tools: []Tool{{Name: "syft"}}, want: SourceSyft},
		{name: "syft cased", tools: []Tool{{Name: "Syft"}}, want: SourceSyft},
		{name: "syft via vendor anchore",
			tools: []Tool{{Vendor: "anchore", Name: "cataloger"}}, want: SourceSyft},
		{name: "trivy bare", tools: []Tool{{Name: "trivy"}}, want: SourceTrivy},
		{name: "trivy via aquasecurity",
			tools: []Tool{{Vendor: "aquasecurity", Name: "scanner"}}, want: SourceTrivy},
		{name: "trivy via 'Aqua Security'",
			tools: []Tool{{Vendor: "Aqua Security", Name: "scanner"}}, want: SourceTrivy},
		{name: "other tool", tools: []Tool{{Name: "cdxgen"}}, want: SourceOther},
		{name: "first match wins",
			tools: []Tool{{Name: "cdxgen"}, {Name: "syft"}}, want: SourceSyft},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sbom *SBOM
			if tc.tools != nil {
				sbom = &SBOM{Metadata: Metadata{Tools: tc.tools}}
			}
			if got := DetectSource(sbom); got != tc.want {
				t.Errorf("DetectSource = %q, want %q", got, tc.want)
			}
		})
	}
}
