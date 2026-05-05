package compliance

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// severityConfig is the on-disk schema for `--compliance-config`.
// Layout:
//
//	compliance:
//	  severity_overrides:
//	    - rule_id: NTIA-SUPPLIER
//	      ecosystem: npm
//	      severity: low
//	    - rule_id: NTIA-VERSION
//	      component_type: file
//	      severity: ignored
//
// Overrides append to the bundled defaults; SeverityPolicy walks the
// rules in order and keeps the LAST match, so YAML overrides beat
// defaults whenever they match. See ADR-0031 for the precedence
// rationale.
type severityConfig struct {
	Compliance struct {
		SeverityOverrides []severityOverride `yaml:"severity_overrides"`
	} `yaml:"compliance"`
}

type severityOverride struct {
	RuleID        string `yaml:"rule_id"`
	ComponentType string `yaml:"component_type"`
	Ecosystem     string `yaml:"ecosystem"`
	Severity      string `yaml:"severity"`
	Reason        string `yaml:"reason,omitempty"`
}

// LoadSeverityPolicyFromFile reads a YAML config and returns the
// default policy with the file's overrides appended. An empty path
// returns the defaults unchanged. A read error or malformed file is
// surfaced — air-gapped CI must fail loudly when a misconfigured
// policy file would otherwise silently degrade the gate.
func LoadSeverityPolicyFromFile(path string) (*SeverityPolicy, error) {
	if path == "" {
		return DefaultSeverityPolicy(), nil
	}
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("compliance-config %q: %w", path, err)
	}
	return LoadSeverityPolicyFromBytes(body)
}

// LoadSeverityPolicyFromBytes parses YAML body and returns the
// default policy with overrides appended. Used by tests + the file
// loader.
func LoadSeverityPolicyFromBytes(body []byte) (*SeverityPolicy, error) {
	var cfg severityConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("compliance-config: parse YAML: %w", err)
	}
	overrides, err := convertOverrides(cfg.Compliance.SeverityOverrides)
	if err != nil {
		return nil, err
	}
	return DefaultSeverityPolicy().WithOverrides(overrides...), nil
}

// convertOverrides validates the YAML overrides and converts them
// into SeverityRule entries. Returns an error on the first invalid
// entry — partial application is worse than a hard fail when the
// operator gets a typo.
func convertOverrides(in []severityOverride) ([]SeverityRule, error) {
	out := make([]SeverityRule, 0, len(in))
	for i, o := range in {
		if o.RuleID == "" {
			return nil, fmt.Errorf("compliance-config: severity_overrides[%d]: rule_id is required", i)
		}
		sev, ok := policy.ParseSeverity(o.Severity)
		if !ok {
			return nil, fmt.Errorf("compliance-config: severity_overrides[%d]: unknown severity %q", i, o.Severity)
		}
		out = append(out, SeverityRule{
			RuleID:        o.RuleID,
			ComponentType: model.ComponentType(o.ComponentType),
			Ecosystem:     o.Ecosystem,
			Severity:      sev,
			Reason:        defaultIfEmpty(o.Reason, "operator override via --compliance-config"),
		})
	}
	return out, nil
}

func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
