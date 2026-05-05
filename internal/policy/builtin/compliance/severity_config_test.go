package compliance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestLoadSeverityPolicyFromBytes_OverridesDefault — the schema
// from ADR-0031: a YAML file defines `compliance.severity_overrides`
// with rule_id / ecosystem / component_type / severity entries that
// beat the bundled defaults.
func TestLoadSeverityPolicyFromBytes_OverridesDefault(t *testing.T) {
	cfg := []byte(`
compliance:
  severity_overrides:
    - rule_id: NTIA-SUPPLIER
      ecosystem: npm
      severity: low
      reason: corp policy upgraded npm tracking
    - rule_id: NTIA-VERSION
      component_type: file
      severity: ignored
`)
	p, err := LoadSeverityPolicyFromBytes(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := &model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:npm/lodash@1"}
	sev, reason, _ := p.Severity("NTIA-SUPPLIER", c)
	if sev != policy.SeverityLow {
		t.Errorf("override severity = %v, want SeverityLow", sev)
	}
	if reason != "corp policy upgraded npm tracking" {
		t.Errorf("override reason = %q", reason)
	}
}

// TestLoadSeverityPolicyFromFile_EmptyPathReturnsDefault — operators
// who don't pass `--compliance-config` still get the bundled policy.
func TestLoadSeverityPolicyFromFile_EmptyPathReturnsDefault(t *testing.T) {
	p, err := LoadSeverityPolicyFromFile("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := &model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:npm/x@1"}
	sev, _, _ := p.Severity("NTIA-SUPPLIER", c)
	if sev != policy.SeverityInfo {
		t.Errorf("default policy severity = %v, want SeverityInfo for npm", sev)
	}
}

func TestLoadSeverityPolicyFromFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compliance.yaml")
	if err := os.WriteFile(path, []byte(`
compliance:
  severity_overrides:
    - rule_id: NTIA-SUPPLIER
      ecosystem: pypi
      severity: high
`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadSeverityPolicyFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	sev, _, _ := p.Severity("NTIA-SUPPLIER",
		&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:pypi/django@5"})
	if sev != policy.SeverityHigh {
		t.Errorf("severity = %v, want SeverityHigh", sev)
	}
}

func TestLoadSeverityPolicy_RejectsMissingRuleID(t *testing.T) {
	_, err := LoadSeverityPolicyFromBytes([]byte(`
compliance:
  severity_overrides:
    - ecosystem: npm
      severity: low
`))
	if err == nil {
		t.Error("expected error on missing rule_id")
	}
}

func TestLoadSeverityPolicy_RejectsUnknownSeverity(t *testing.T) {
	_, err := LoadSeverityPolicyFromBytes([]byte(`
compliance:
  severity_overrides:
    - rule_id: NTIA-SUPPLIER
      severity: blocker
`))
	if err == nil {
		t.Error("expected error on unknown severity name")
	}
}

func TestLoadSeverityPolicy_FileNotFound(t *testing.T) {
	_, err := LoadSeverityPolicyFromFile("/no/such/file/at/all.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadSeverityPolicy_MalformedYAML(t *testing.T) {
	_, err := LoadSeverityPolicyFromBytes([]byte("not: valid: yaml: at: all"))
	if err == nil {
		t.Error("expected parse error on malformed YAML")
	}
}
