package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/license"
	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestApplyLicenseGate_DenyEmitsLicenseViolation — a deny-listed
// SPDX produces a synthetic LICENSE-VIOLATION-<...> finding the
// compliance gate then counts. ADR-0065.
func TestApplyLicenseGate_DenyEmitsLicenseViolation(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef: "c-gpl",
				Name:   "gpl-pkg",
				PURL:   "pkg:npm/gpl-pkg@1.0",
				Licenses: []model.License{
					{SPDXID: "GPL-3.0-only"},
				},
			},
			{
				BOMRef: "c-mit",
				Name:   "mit-pkg",
				PURL:   "pkg:npm/mit-pkg@1.0",
				Licenses: []model.License{
					{SPDXID: "MIT"},
				},
			},
		},
	}
	var findings []policy.Finding
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	denied := applyLicenseGate(sbom, &findings, license.Options{
		Deny: []string{"GPL-3.0-only"},
	}, logger)

	if denied != 1 {
		t.Errorf("denied count = %d, want 1", denied)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 synthetic LICENSE-VIOLATION", findings)
	}
	if !strings.HasPrefix(findings[0].RuleID, "LICENSE-VIOLATION-") {
		t.Errorf("rule ID = %q, want LICENSE-VIOLATION- prefix", findings[0].RuleID)
	}
	if findings[0].Severity != policy.SeverityHigh {
		t.Errorf("severity = %v, want SeverityHigh", findings[0].Severity)
	}
	if got := sbom.Metadata.Properties["astinus:license:total-denied"]; got != "1" {
		t.Errorf("total-denied = %q, want 1", got)
	}
	if got := sbom.Metadata.Properties["astinus:license:total-evaluated"]; got != "2" {
		t.Errorf("total-evaluated = %q, want 2", got)
	}
	if got := sbom.Metadata.Properties["astinus:license:gate-mode"]; got != "deny" {
		t.Errorf("gate-mode = %q, want deny", got)
	}
	denyKey := "astinus:license:denied:pkg:npm/gpl-pkg@1.0"
	if got := sbom.Metadata.Properties[denyKey]; !strings.Contains(got, "GPL-3.0-only") {
		t.Errorf("%s = %q, want mention of GPL-3.0-only", denyKey, got)
	}
}

func TestApplyLicenseGate_DisabledNoOp(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{Name: "x"}},
	}
	findings := []policy.Finding{}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	denied := applyLicenseGate(sbom, &findings, license.Options{}, logger)
	if denied != 0 || len(findings) != 0 {
		t.Errorf("disabled gate produced findings=%v denied=%d", findings, denied)
	}
	if sbom.Metadata.Properties["astinus:license:gate-mode"] != "" {
		t.Errorf("disabled gate stamped gate-mode metadata")
	}
}

func TestApplyLicenseGate_RequireKnownDeniesEmpty(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{BOMRef: "c1", Name: "no-license", PURL: "pkg:npm/no-license@1.0"},
		},
	}
	findings := []policy.Finding{}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	denied := applyLicenseGate(sbom, &findings, license.Options{RequireKnown: true}, logger)
	if denied != 1 {
		t.Errorf("denied = %d, want 1", denied)
	}
	if got := sbom.Metadata.Properties["astinus:license:gate-mode"]; got != "require-known" {
		t.Errorf("gate-mode = %q, want require-known", got)
	}
}

func TestApplyLicenseGate_UnknownStampsWarnNotDenied(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef:   "c1",
				Name:     "mystery",
				PURL:     "pkg:npm/mystery@1.0",
				Licenses: []model.License{{Expression: "MIT OR 1stPlace"}},
			},
		},
	}
	findings := []policy.Finding{}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	denied := applyLicenseGate(sbom, &findings, license.Options{
		Deny: []string{"GPL-3.0-only"}, // mystery isn't GPL, but expression unparseable
	}, logger)
	if denied != 0 {
		t.Errorf("unparseable license incorrectly denied (count=%d)", denied)
	}
	if got := sbom.Metadata.Properties["astinus:license:total-unknown"]; got != "1" {
		t.Errorf("total-unknown = %q, want 1", got)
	}
	unknownKey := "astinus:license:unknown:pkg:npm/mystery@1.0"
	if got := sbom.Metadata.Properties[unknownKey]; got == "" {
		t.Errorf("%s missing — unknown stamp not written", unknownKey)
	}
}

func TestSanitiseRuleIDTail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pkg:npm/foo@1.0", "pkg-npm-foo-1-0"},
		{"FOO", "foo"},
		{"", "unknown"},
		{"@#$%", "unknown"},
		{"--leading", "leading"},
		{"name with spaces", "name-with-spaces"},
	}
	for _, c := range cases {
		if got := sanitiseRuleIDTail(c.in); got != c.want {
			t.Errorf("sanitiseRuleIDTail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDescribeLicenseMode(t *testing.T) {
	cases := []struct {
		opts license.Options
		want string
	}{
		{license.Options{Allow: []string{"MIT"}}, "allow"},
		{license.Options{Deny: []string{"GPL-3.0-only"}}, "deny"},
		{license.Options{RequireKnown: true}, "require-known"},
		{license.Options{
			Allow: []string{"MIT"}, Deny: []string{"GPL-3.0-only"}, RequireKnown: true,
		}, "allow+deny+require-known"},
		{license.Options{}, "disabled"},
	}
	for _, c := range cases {
		if got := describeLicenseMode(c.opts); got != c.want {
			t.Errorf("describeLicenseMode(%+v) = %q, want %q", c.opts, got, c.want)
		}
	}
}
