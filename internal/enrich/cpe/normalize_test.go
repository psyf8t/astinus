package cpe

import "testing"

// TestNormalizeCPEEncoding_DecodesAndReEscapes — S7 Task 1. Input
// CPEs with URL-percent encoding get re-emitted with spec-correct
// backslash-escape. ADR-0058 amendment.
func TestNormalizeCPEEncoding_DecodesAndReEscapes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Debian epoch — `%3A` → `\:`, `%2B` → `\+`.
		{
			`cpe:2.3:a:libcap2:libcap2:1%3A2.75-10%2Bb8:*:*:*:*:*:*:*`,
			`cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`,
		},
		// libev4 reproducer from run-2.
		{
			`cpe:2.3:a:libev:libev4:1%3A4.33-1:*:*:*:*:*:*:*`,
			`cpe:2.3:a:libev:libev4:1\:4.33-1:*:*:*:*:*:*:*`,
		},
		// Already spec-correct — passthrough.
		{
			`cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`,
			`cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`,
		},
		// No special characters — passthrough.
		{
			`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
			`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
		},
		// Wildcard / non-applicable sentinels untouched.
		{
			`cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*`,
			`cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*`,
		},
	}
	for _, c := range cases {
		got, changed := NormalizeCPEEncoding(c.in)
		if got != c.want {
			t.Errorf("NormalizeCPEEncoding(%q) = %q, want %q", c.in, got, c.want)
		}
		wantChanged := c.in != c.want
		if changed != wantChanged {
			t.Errorf("NormalizeCPEEncoding(%q) changed=%v, want %v", c.in, changed, wantChanged)
		}
	}
}

// TestNormalizeCPEEncoding_LeavesNonCPEAlone — strings that don't
// parse as CPE 2.3 pass through unchanged. The validator decides
// downstream.
func TestNormalizeCPEEncoding_LeavesNonCPEAlone(t *testing.T) {
	cases := []string{
		"",
		"not a cpe at all",
		"cpe:2.3:a:short",            // not enough slots
		"some-string-with-%3A-in-it", // not CPE-shaped
	}
	for _, in := range cases {
		got, changed := NormalizeCPEEncoding(in)
		if got != in {
			t.Errorf("NormalizeCPEEncoding(%q) = %q, want passthrough", in, got)
		}
		if changed {
			t.Errorf("NormalizeCPEEncoding(%q) changed=true, want false for passthrough", in)
		}
	}
}

// TestNormalizeCPEEncoding_FastPath — no `%` in the input means
// no decoding work, no allocation. Pin the contract so a future
// implementation tweak doesn't accidentally heap-allocate on the
// common case.
func TestNormalizeCPEEncoding_FastPath(t *testing.T) {
	in := `cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`
	got, changed := NormalizeCPEEncoding(in)
	if got != in {
		t.Errorf("fast path produced %q, want %q", got, in)
	}
	if changed {
		t.Errorf("fast path reported changed=true, want false")
	}
}

// TestPercentDecodeCPESlot pins the per-slot decode behaviour
// directly. Recognised triplets decode; unrecognised triplets
// pass through.
func TestPercentDecodeCPESlot(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1%3A2.75-10%2Bb8", "1:2.75-10+b8"},
		{"%40version", "@version"},
		{"%5Cescaped", `\escaped`},
		{"no-percents", "no-percents"},
		// %99 isn't in the decode map — passthrough.
		{"keep-%99-as-is", "keep-%99-as-is"},
		// Trailing % without a triplet — passthrough.
		{"trailing-%", "trailing-%"},
		// Empty.
		{"", ""},
	}
	for _, c := range cases {
		if got := percentDecodeCPESlot(c.in); got != c.want {
			t.Errorf("percentDecodeCPESlot(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCandidatesFromExistingCPEs_NormalisesInput — the integration
// pin: an upstream-supplied CPE with URL-percent encoding lands in
// the candidate slate as a spec-correct backslash-escaped string.
// ADR-0058 amendment.
func TestCandidatesFromExistingCPEs_NormalisesInput(t *testing.T) {
	in := []string{
		`cpe:2.3:a:libcap2:libcap2:1%3A2.75-10%2Bb8:*:*:*:*:*:*:*`,
	}
	got, normalised := candidatesFromExistingCPEs(in)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	want := `cpe:2.3:a:libcap2:libcap2:1\:2.75-10\+b8:*:*:*:*:*:*:*`
	if got[0].CPE != want {
		t.Errorf("Candidate.CPE = %q, want %q", got[0].CPE, want)
	}
	if got[0].Confidence == ConfidenceReject {
		t.Errorf("normalised input incorrectly rejected: %+v", got[0])
	}
	if normalised != 1 {
		t.Errorf("normalised count = %d, want 1", normalised)
	}
}
