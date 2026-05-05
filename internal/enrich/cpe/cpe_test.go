package cpe

import "testing"

func TestIsValidCPE(t *testing.T) {
	good := []string{
		"cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*",
		"cpe:2.3:*:*:*:*:*:*:*:*:*:*:*",
	}
	for _, c := range good {
		if !IsValidCPE(c) {
			t.Errorf("IsValidCPE(%q) = false, want true", c)
		}
	}
	bad := []string{
		"",
		"cpe:2.2:a:foo:bar:1.0",               // wrong version
		"cpe:2.3:x:foo:bar:1.0:*:*:*:*:*:*:*", // bad part
		"cpe:2.3:a:foo:bar:1.0:*:*:*:*:*:*",   // 10 attrs not 11
		"cpe:2.3:a:foo:bar:1.0:*:*:*:*:*:*:*:extra", // extra attr
	}
	for _, c := range bad {
		if IsValidCPE(c) {
			t.Errorf("IsValidCPE(%q) = true, want false", c)
		}
	}
}

func TestParseAndStringRoundTrip(t *testing.T) {
	in := "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*"
	c, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Vendor != "expressjs" || c.Product != "express" || c.Version != "4.18.2" {
		t.Errorf("parsed = %+v", c)
	}
	if c.String() != in {
		t.Errorf("round-trip: %q vs %q", c.String(), in)
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse("not a cpe"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuild(t *testing.T) {
	got := Build("Apache", "Log4j", "2.17.1")
	want := "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("Build = %q, want %q", got, want)
	}
}

func TestBuildEmptyVersion(t *testing.T) {
	got := Build("expressjs", "express", "")
	want := "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("Build = %q, want %q", got, want)
	}
}

func TestStringFillsWildcards(t *testing.T) {
	c := CPEv23{Part: "a", Vendor: "x", Product: "y"}
	want := "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"
	if got := c.String(); got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}
