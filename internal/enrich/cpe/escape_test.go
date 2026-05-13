package cpe

import "testing"

func TestEscapeCPE23Attribute(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "*"},
		{"*", "*"},
		{"-", "-"},
		{"normal", "normal"},
		{"1.2.3", "1.2.3"},
		// Run-#4 reproducer set (Debian epoch + plus-sign versions).
		{"1:2.75-10+b8", `1\:2.75-10\+b8`},
		{"1:4.0.2-2", `1\:4.0.2-2`},
		{"1:1.3.dfsg+really1.3.1-1+b1", `1\:1.3.dfsg\+really1.3.1-1\+b1`},
		// v-prefix is NOT a CPE 2.3 special character; preserve.
		{"v1.2.3", "v1.2.3"},
		// Space is NOT a CPE 2.3 special character (the URI binding
		// rules elsewhere replace it with `_`, but that's upstream of
		// this helper).
		{"foo bar", "foo bar"},
		// One example from each kind of special char so a future
		// table edit immediately surfaces if the set changes.
		{"a:b", `a\:b`},
		{"a+b", `a\+b`},
		{"a@b", `a\@b`},
		{"a?b", `a\?b`},
		{"a/b", `a\/b`},
		// Already-escaped input doubles the backslash — that's the
		// idempotency caveat documented in the helper.
		{`a\:b`, `a\\\:b`},
	}
	for _, tc := range cases {
		if got := EscapeCPE23Attribute(tc.in); got != tc.want {
			t.Errorf("EscapeCPE23Attribute(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnescapeCPE23Attribute(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"*", "*"},
		{"-", "-"},
		{"normal", "normal"},
		{`1\:2.75-10\+b8`, "1:2.75-10+b8"},
		{`a\\b`, `a\b`}, // escaped backslash → literal backslash
		// Trailing single backslash is preserved as literal so we
		// don't silently drop data on a malformed input.
		{`incomplete\`, `incomplete\`},
	}
	for _, tc := range cases {
		if got := UnescapeCPE23Attribute(tc.in); got != tc.want {
			t.Errorf("UnescapeCPE23Attribute(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEscapeCPE23Attribute_RoundTrip(t *testing.T) {
	inputs := []string{
		"1:2.75-10+b8",
		"1:4.0.2-2",
		"1:1.3.dfsg+really1.3.1-1+b1",
		"8.17.0-r1",
		"1.2.3",
		"v1.9.3",
		"x@y/z",
		"only:colons:everywhere",
	}
	for _, s := range inputs {
		got := UnescapeCPE23Attribute(EscapeCPE23Attribute(s))
		if got != s {
			t.Errorf("round-trip %q → %q (escape: %q)",
				s, got, EscapeCPE23Attribute(s))
		}
	}
}

// TestBuild_DebEpoch pins the operator-visible CPE shape for the
// run-#4 reproducer set. Pre-S6-T1 these versions either rendered
// with literal colons (and failed validation downstream) or carried
// `%3A` percent-encoded values on environments that fed through a
// URL-encoding layer. ADR-0058 mandates backslash-escape.
func TestBuild_DebEpoch(t *testing.T) {
	cases := []struct {
		vendor, product, version, want string
	}{
		{
			"libcap2", "libcap2", "1:2.75-10+b8",
			`cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`,
		},
		{
			"libaudit-common", "libaudit-common", "1:4.0.2-2",
			`cpe:2.3:a:libaudit-common:libaudit-common:1\:4.0.2-2:*:*:*:*:*:*:*`,
		},
		{
			"zlib1g", "zlib1g", "1:1.3.dfsg+really1.3.1-1+b1",
			`cpe:2.3:a:zlib1g:zlib1g:1\:1.3.dfsg\+really1.3.1-1\+b1:*:*:*:*:*:*:*`,
		},
		// Non-deb baseline — no special characters, no escape, no
		// behaviour change relative to pre-S6 builds.
		{
			"openssl", "openssl", "3.0.0",
			`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
		},
		// Sprint 5 Task 0 stdlib coordinate — version string carries
		// no special chars; the keep-primary stamp pin must keep
		// working byte-for-byte.
		{
			"golang", "go", "1.21.5",
			`cpe:2.3:a:golang:go:1.21.5:*:*:*:*:*:*:*`,
		},
	}
	for _, tc := range cases {
		if got := Build(tc.vendor, tc.product, tc.version); got != tc.want {
			t.Errorf("Build(%q, %q, %q) = %q, want %q",
				tc.vendor, tc.product, tc.version, got, tc.want)
		}
	}
}

// TestBuild_NoURLPercentEncoding asserts that the operator-visible
// CPE never carries `%xx` URL-percent sequences. ADR-0058.
func TestBuild_NoURLPercentEncoding(t *testing.T) {
	special := []string{"1:2.75-10+b8", "x@y", "a?b", "a/b", "1:0", "p+q"}
	for _, v := range special {
		got := Build("vendor", "product", v)
		for _, bad := range []string{"%3A", "%2B", "%40", "%3F", "%2F", "%20"} {
			if containsCaseInsensitive(got, bad) {
				t.Errorf("Build(version=%q) = %q — URL-percent sequence %q leaked",
					v, got, bad)
			}
		}
	}
}

// TestIsValidCPE_AcceptsEscapedColons asserts the validator accepts
// `\:` inside a slot value — pre-S6 the relaxed regex `[^:]*`
// rejected any literal colon, which broke acceptance of valid
// Debian-epoch CPEs Astinus itself produces. ADR-0058.
func TestIsValidCPE_AcceptsEscapedColons(t *testing.T) {
	cases := []struct {
		cpe string
		ok  bool
	}{
		{`cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`, true},
		{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", true},
		{"cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", true},
		// Unescaped colon mid-slot — splits into too many slots.
		{"cpe:2.3:a:vendor:product:1:2.3:*:*:*:*:*:*:*", false},
		// Trailing backslash with nothing after it.
		{`cpe:2.3:a:v:p:bad\`, false},
		// Wrong number of slots.
		{"cpe:2.3:a:vendor:product:1.0.0:*:*:*", false},
	}
	for _, tc := range cases {
		if got := IsValidCPE(tc.cpe); got != tc.ok {
			t.Errorf("IsValidCPE(%q) = %v, want %v", tc.cpe, got, tc.ok)
		}
	}
}

// TestParse_UnescapesAttributes asserts Parse returns human-readable
// attribute values (not the escaped wire form). ADR-0058.
func TestParse_UnescapesAttributes(t *testing.T) {
	cpe := `cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`
	p, err := Parse(cpe)
	if err != nil {
		t.Fatalf("Parse(%q): %v", cpe, err)
	}
	if p.Vendor != "libcap2" || p.Product != "libcap2" {
		t.Errorf("Parse vendor/product = %q/%q, want libcap2/libcap2",
			p.Vendor, p.Product)
	}
	if p.Version != "1:2.75-10+b8" {
		t.Errorf("Parse version = %q, want %q", p.Version, "1:2.75-10+b8")
	}
	// Round-trip: re-stringify must produce a spec-correct shape that
	// equals the original (after normalising empty slots to `*`).
	if got := p.String(); got != cpe {
		t.Errorf("Parse → String round-trip = %q, want %q", got, cpe)
	}
}

// TestApplyVersionNormalization_HonoursEscapes — go-buildinfo passes
// a `v`-prefixed version through; the policy strips it. Run on a
// deb-epoch CPE the helper must keep the colon-escape intact while
// touching only the version slot. S5-T3 / ADR-0050 + ADR-0058.
func TestApplyVersionNormalization_HonoursEscapes(t *testing.T) {
	in := `cpe:2.3:a:vendor:product:v1\:2.3-4\+b1:*:*:*:*:*:*:*`
	want := `cpe:2.3:a:vendor:product:1\:2.3-4\+b1:*:*:*:*:*:*:*`
	got := applyVersionNormalization(in, func(v string) string {
		// Mimic the go-buildinfo policy's NormalizeVersion: strip
		// leading "v". We're handed the UNESCAPED form here.
		if len(v) > 0 && v[0] == 'v' {
			return v[1:]
		}
		return v
	})
	if got != want {
		t.Errorf("applyVersionNormalization = %q, want %q", got, want)
	}
}

func TestCpeVendor_UnescapesAndLowercases(t *testing.T) {
	cases := []struct{ cpe, want string }{
		{"cpe:2.3:a:GNU:bash:5.2:*:*:*:*:*:*:*", "gnu"},
		{`cpe:2.3:a:VENDOR\:WITH\:COLON:product:1.0:*:*:*:*:*:*:*`, "vendor:with:colon"},
		{"not-a-cpe", ""},
	}
	for _, tc := range cases {
		if got := cpeVendor(tc.cpe); got != tc.want {
			t.Errorf("cpeVendor(%q) = %q, want %q", tc.cpe, got, tc.want)
		}
	}
}

func containsCaseInsensitive(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a := haystack[i+j]
			b := needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
