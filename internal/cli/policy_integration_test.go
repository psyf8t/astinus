package cli

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestApplyPolicies_DenyAddsSyntheticFinding — a deny rule against
// a matching component must produce a `POLICY-<rule-id>` finding
// the gate then counts. ADR-0064.
func TestApplyPolicies_DenyAddsSyntheticFinding(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c-log4j",
			Name:    "log4j-core",
			Version: "2.14.1",
			PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		}},
	}
	pol := &policy.Policy{
		Version: "1",
		Name:    "test",
		Rules: []policy.Rule{{
			ID: "deny-old-log4j",
			When: policy.When{
				Component: &policy.ComponentMatcher{
					PURLMatches:  "pkg:maven/org.apache.logging.log4j/log4j-core@*",
					VersionBelow: "2.17.0",
				},
			},
			Action: policy.Action{
				Type:    policy.ActionDeny,
				Message: "log4j < 2.17.0 forbidden",
			},
		}},
		SourcePath: "/policies/log4j.yaml",
	}
	findings := []policy.Finding{}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	allowed, denied := applyPolicies(sbom, &findings, []*policy.Policy{pol}, logger)

	if len(findings) != 1 || findings[0].RuleID != "POLICY-deny-old-log4j" {
		t.Errorf("findings = %+v, want one POLICY-deny-old-log4j entry", findings)
	}
	if findings[0].Severity != policy.SeverityHigh {
		t.Errorf("synthetic finding severity = %v, want SeverityHigh", findings[0].Severity)
	}
	if _, ok := denied["POLICY-deny-old-log4j"]; !ok {
		t.Errorf("denied set = %v, want POLICY-deny-old-log4j", denied)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed set non-empty: %v", allowed)
	}
	if got := sbom.Metadata.Properties["astinus:policy:hit:deny-old-log4j"]; got == "" {
		t.Error("hit:deny-old-log4j stamp missing")
	}
	if got := sbom.Metadata.Properties["astinus:policy:total-hits"]; got == "" {
		t.Error("total-hits stamp missing")
	}
}

// TestApplyPolicies_AllowSuppressesCVE — an allow rule on a
// CVE-shaped finding via FindingMatcher results in the finding's
// RuleID landing in the allowed set, where the gate then
// subtracts it from the hit count. ADR-0064.
func TestApplyPolicies_AllowSuppressesCVE(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c-openssl",
			Name:    "openssl",
			Version: "3.0.0",
			PURL:    "pkg:apk/alpine/openssl@3.0.0",
			Properties: map[string]string{
				"astinus:origin": "base",
			},
		}},
	}
	pol := &policy.Policy{
		Version: "1",
		Name:    "test",
		Rules: []policy.Rule{{
			ID: "allow-base-cve",
			When: policy.When{
				All: []policy.When{
					{Finding: &policy.FindingMatcher{IDPrefix: "CVE-"}},
					{Component: &policy.ComponentMatcher{HasProperty: &policy.PropertyMatcher{
						Name: "astinus:origin", Value: "base",
					}}},
				},
			},
			Action: policy.Action{Type: policy.ActionAllow, Message: "vendor"},
		}},
		SourcePath: "/policies/allow-base.yaml",
	}
	findings := []policy.Finding{
		{Severity: policy.SeverityHigh, RuleID: "CVE-2024-12345", Component: "c-openssl"},
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	allowed, denied := applyPolicies(sbom, &findings, []*policy.Policy{pol}, logger)

	if _, ok := allowed["CVE-2024-12345"]; !ok {
		t.Errorf("allowed = %v, want CVE-2024-12345", allowed)
	}
	if len(denied) != 0 {
		t.Errorf("denied = %v, want empty", denied)
	}
	if got := sbom.Metadata.Properties["astinus:policy:hit:allow-base-cve"]; got == "" {
		t.Error("hit:allow-base-cve stamp missing")
	}
}

// TestApplyPolicies_NonMatchingNoEffect — a policy whose rules
// don't match the component / findings produces no decisions,
// no metadata stamps, no synthetic findings.
func TestApplyPolicies_NonMatchingNoEffect(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "c", PURL: "pkg:npm/express@4.18.2",
		}},
	}
	pol := &policy.Policy{
		Version: "1", Name: "test",
		Rules: []policy.Rule{{
			ID: "deny-php",
			When: policy.When{Component: &policy.ComponentMatcher{
				Ecosystem: "composer",
			}},
			Action: policy.Action{Type: policy.ActionDeny},
		}},
	}
	findings := []policy.Finding{}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	allowed, denied := applyPolicies(sbom, &findings, []*policy.Policy{pol}, logger)

	if len(findings) != 0 {
		t.Errorf("findings = %+v, want empty", findings)
	}
	if len(allowed) != 0 || len(denied) != 0 {
		t.Errorf("allowed=%v denied=%v, want both empty", allowed, denied)
	}
	if got := sbom.Metadata.Properties["astinus:policy:total-hits"]; got != "" {
		t.Errorf("total-hits stamped on no-match run: %q", got)
	}
}

// TestApplyPolicies_EmptyPoliciesIsNoOp — passing nil/empty
// policies leaves findings + metadata unchanged.
func TestApplyPolicies_EmptyPoliciesIsNoOp(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{BOMRef: "c"}}}
	findings := []policy.Finding{{RuleID: "NTIA-VERSION"}}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	allowed, denied := applyPolicies(sbom, &findings, nil, logger)
	if len(findings) != 1 || len(allowed) != 0 || len(denied) != 0 {
		t.Errorf("empty-policies run mutated state: findings=%+v allowed=%v denied=%v",
			findings, allowed, denied)
	}

	allowed, denied = applyPolicies(sbom, &findings, []*policy.Policy{}, logger)
	if len(allowed) != 0 || len(denied) != 0 {
		t.Errorf("empty-slice run mutated state: allowed=%v denied=%v",
			allowed, denied)
	}
}

// TestIndexComponentsByBOMRef pins the helper used by the
// per-finding policy evaluation path. Resolves BOMRef → *Component
// recursively through SubComponents.
func TestIndexComponentsByBOMRef(t *testing.T) {
	comps := []model.Component{
		{BOMRef: "parent", Name: "parent"},
		{
			BOMRef: "container",
			SubComponents: []model.Component{
				{BOMRef: "child", Name: "child"},
			},
		},
		// No BOMRef — excluded from the index.
		{Name: "anonymous"},
	}
	idx := indexComponentsByBOMRef(comps)
	if len(idx) != 3 {
		t.Errorf("indexed %d, want 3 (parent, container, child)", len(idx))
	}
	if got := idx["child"]; got == nil || got.Name != "child" {
		t.Errorf("child lookup miss; got %+v", got)
	}
	if got := idx[""]; got != nil {
		t.Errorf("anonymous (no BOMRef) found in index: %+v", got)
	}
}
