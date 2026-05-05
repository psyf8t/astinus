package compliance

import (
	"strings"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// SeverityPolicy decides per-finding severity based on the rule that
// fired and the Component the finding names. Centralised so the
// validators stay simple (they emit findings with a default severity)
// and the post-processing in the compliance enricher applies
// contextual adjustments.
//
// Sprint 3 Task 2: introduced to fix the v0.2 benchmark output where
// blanket SeverityMedium for every NTIA-SUPPLIER finding produced
// 11949 findings on 5800 components — most of them noise (npm
// packages don't have NTIA-supplier semantics, files don't have
// supplier semantics at all). The policy reduces actionable findings
// by ~10× without losing any genuinely-flagging ones. ADR-0031.
type SeverityPolicy struct {
	rules []SeverityRule
}

// SeverityRule is one entry in a SeverityPolicy. The first rule
// whose RuleID + ComponentType + Ecosystem all match becomes the
// chosen severity. Empty ComponentType / Ecosystem is a wildcard.
//
// "Most specific match" is encoded by rule order — defaultPolicy
// puts ecosystem-specific rules BEFORE the type-only fallback,
// before the rule-only catch-all. The policy iterates in order and
// keeps the LAST match, so wildcards lose to specifics.
type SeverityRule struct {
	RuleID        string              // e.g. "NTIA-SUPPLIER"
	ComponentType model.ComponentType // "library" / "application" / "file" / "" (any)
	Ecosystem     string              // "npm" / "deb" / "" (any)
	Severity      policy.Severity
	Reason        string
}

// NewSeverityPolicy returns a policy with the supplied rules.
// Constructors that build a policy from rule slices (defaults +
// overrides) consume this.
func NewSeverityPolicy(rules ...SeverityRule) *SeverityPolicy {
	return &SeverityPolicy{rules: append([]SeverityRule(nil), rules...)}
}

// DefaultSeverityPolicy returns the bundled per-ecosystem severity
// matrix that addresses the Sprint 2 benchmark noise. The rules are
// ordered from most-specific (component-type + ecosystem) to most-
// generic (rule-only catch-all); Severity() walks them in order and
// keeps the last match so the most specific rule always wins.
func DefaultSeverityPolicy() *SeverityPolicy {
	return NewSeverityPolicy(defaultRules()...)
}

// Severity returns (severity, reason, matched). When no rule
// matches, matched=false and the caller should preserve the
// finding's original severity — the policy stays out of the way of
// custom validators with rule IDs the bundled policy doesn't know
// about.
//
// c may be nil (SBOM-level finding). In that case ComponentType /
// Ecosystem rules don't match; only RuleID-only rules apply.
func (p *SeverityPolicy) Severity(ruleID string, c *model.Component) (policy.Severity, string, bool) {
	if p == nil || len(p.rules) == 0 {
		return policy.SeverityInfo, "", false
	}
	componentType, ecosystem := componentContext(c)

	var bestSev policy.Severity
	bestReason := ""
	matched := false

	for _, r := range p.rules {
		if r.RuleID != ruleID {
			continue
		}
		if r.ComponentType != "" && r.ComponentType != componentType {
			continue
		}
		if r.Ecosystem != "" && r.Ecosystem != ecosystem {
			continue
		}
		bestSev = r.Severity
		bestReason = r.Reason
		matched = true
	}
	return bestSev, bestReason, matched
}

// Rules returns a defensive copy of the policy's rule slate. Used by
// tests + diagnostic CLI surfaces.
func (p *SeverityPolicy) Rules() []SeverityRule {
	out := make([]SeverityRule, len(p.rules))
	copy(out, p.rules)
	return out
}

// WithOverrides returns a new policy whose rules are the bundled
// defaults plus overrides appended at the end. Because Severity()
// keeps the LAST matching rule, override entries beat defaults
// whenever they match. Used by the YAML loader for
// `--compliance-config`.
func (p *SeverityPolicy) WithOverrides(overrides ...SeverityRule) *SeverityPolicy {
	combined := append([]SeverityRule(nil), p.rules...)
	combined = append(combined, overrides...)
	return &SeverityPolicy{rules: combined}
}

// componentContext extracts (type, ecosystem) from a Component for
// rule matching. Empty strings when the Component is nil or the
// signal is missing — wildcard rules still match.
func componentContext(c *model.Component) (model.ComponentType, string) {
	if c == nil {
		return "", ""
	}
	return c.Type, ecosystemFromPURL(c.PURL)
}

// ecosystemFromPURL returns the type segment of a PURL (`pkg:<type>/...`)
// or empty when the PURL is missing / malformed. Lowercased so YAML
// rules match regardless of the operator's casing.
func ecosystemFromPURL(purl string) string {
	if purl == "" {
		return ""
	}
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	idx := strings.IndexAny(rest, "/@?#")
	if idx < 0 {
		return strings.ToLower(rest)
	}
	return strings.ToLower(rest[:idx])
}

// defaultRules is the bundled severity matrix. Documented in
// ADR-0031 §3 (severity table) — operators looking to tune via
// `--compliance-config` start by reading this list and adding
// overrides for their ecosystems.
func defaultRules() []SeverityRule {
	rules := append([]SeverityRule{}, ntiaSupplierRules()...)
	rules = append(rules, ntiaVersionRules()...)
	rules = append(rules, ntiaIdentifierRules()...)
	rules = append(rules, ntiaMiscRules()...)
	rules = append(rules, spdxRules()...)
	rules = append(rules, euCRARules()...)
	return rules
}

// ntiaSupplierRules covers the rule that produced the bulk of the
// Sprint 2 benchmark noise. Per-ecosystem severity reflects whether
// the registry has a useful "supplier" concept and whether Astinus
// can derive it via the Sprint 3 Task 4 enrichment.
func ntiaSupplierRules() []SeverityRule {
	const id = "NTIA-SUPPLIER"
	return []SeverityRule{
		// Catch-all default — overridden by more-specific entries below.
		{RuleID: id, Severity: policy.SeverityMedium,
			Reason: "default for unknown ecosystem"},

		// type=file: the rule does not apply to forensic file rows.
		{RuleID: id, ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored,
			Reason:   "files have no NTIA-supplier semantics"},

		// Package ecosystems where supplier is auto-derivable from
		// the registry / namespace / distro publisher.
		{RuleID: id, Ecosystem: "npm", Severity: policy.SeverityInfo,
			Reason: "npm packages: registry publisher info available via enrichment"},
		{RuleID: id, Ecosystem: "pypi", Severity: policy.SeverityInfo,
			Reason: "PyPI: supplier derivable via enrichment"},
		{RuleID: id, Ecosystem: "deb", Severity: policy.SeverityInfo,
			Reason: "Debian packages: supplier=Debian Project (auto-derivable)"},
		{RuleID: id, Ecosystem: "rpm", Severity: policy.SeverityInfo,
			Reason: "RPM packages: supplier=distro publisher (auto-derivable)"},
		{RuleID: id, Ecosystem: "apk", Severity: policy.SeverityInfo,
			Reason: "Alpine packages: supplier=Alpine Linux (auto-derivable)"},

		// Ecosystems where namespace/groupId hints at supplier but
		// not exactly — operators can supplement.
		{RuleID: id, Ecosystem: "maven", Severity: policy.SeverityLow,
			Reason: "Maven groupId provides supplier indication"},
		{RuleID: id, Ecosystem: "cargo", Severity: policy.SeverityLow},
		{RuleID: id, Ecosystem: "gem", Severity: policy.SeverityLow},
		{RuleID: id, Ecosystem: "nuget", Severity: policy.SeverityLow},

		// Go modules: VCS host (github.com/X) is the de facto supplier.
		{RuleID: id, Ecosystem: "golang", Severity: policy.SeverityMedium,
			Reason: "Go modules: supplier from VCS host (github.com/X)"},

		// Applications without a known supplier are a real
		// compliance gap — that's where security teams want focus.
		{RuleID: id, ComponentType: model.ComponentTypeApplication,
			Severity: policy.SeverityHigh,
			Reason:   "applications must have a known supplier"},
	}
}

// ntiaVersionRules: missing version on a library is high severity;
// on an application it's critical (you can't track CVE applicability
// for an unversioned application). Files are ignored.
func ntiaVersionRules() []SeverityRule {
	const id = "NTIA-VERSION"
	return []SeverityRule{
		{RuleID: id, Severity: policy.SeverityHigh,
			Reason: "missing version blocks vulnerability scanning"},
		{RuleID: id, ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored,
			Reason:   "files have no version semantics"},
		{RuleID: id, ComponentType: model.ComponentTypeApplication,
			Severity: policy.SeverityCritical,
			Reason:   "applications without version are unscannable"},
	}
}

// ntiaIdentifierRules: missing PURL/CPE means the Component cannot
// be vuln-scanned at all. High severity always (except files, which
// don't get scanned in the first place).
func ntiaIdentifierRules() []SeverityRule {
	const id = "NTIA-IDENTIFIER"
	return []SeverityRule{
		{RuleID: id, Severity: policy.SeverityHigh,
			Reason: "components without PURL/CPE/SWID cannot be vulnerability-scanned"},
		{RuleID: id, ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored,
			Reason:   "files don't carry PURL/CPE identifiers"},
	}
}

// ntiaMiscRules covers the SBOM-level NTIA elements (no Component
// in scope; only the RuleID-only rules apply).
func ntiaMiscRules() []SeverityRule {
	return []SeverityRule{
		{RuleID: "NTIA-NAME", Severity: policy.SeverityCritical,
			Reason: "Component lacks name (structural)"},
		{RuleID: "NTIA-METADATA-AUTHOR", Severity: policy.SeverityHigh,
			Reason: "SBOM lacks author metadata"},
		{RuleID: "NTIA-METADATA-TIMESTAMP", Severity: policy.SeverityHigh,
			Reason: "SBOM lacks timestamp"},
		{RuleID: "NTIA-RELATIONSHIPS", Severity: policy.SeverityMedium,
			Reason: "large SBOM with no recorded relationships"},
	}
}

// spdxRules: the SPDX structural validator emits a few low-priority
// findings; no per-ecosystem nuance needed but type=file should be
// ignored consistently.
func spdxRules() []SeverityRule {
	return []SeverityRule{
		{RuleID: "SPDX-LICENSE-NOASSERTION", Severity: policy.SeverityLow,
			Reason: "license missing — registry enrichment can resolve"},
		{RuleID: "SPDX-LICENSE-NOASSERTION", ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored,
			Reason:   "files have no license semantics"},
		{RuleID: "SPDX-DOWNLOAD-LOCATION-NOASSERTION", Severity: policy.SeverityLow,
			Reason: "download location missing"},
		{RuleID: "SPDX-DOWNLOAD-LOCATION-NOASSERTION", ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored},
		{RuleID: "SPDX-PACKAGE-NAME-MISSING", Severity: policy.SeverityCritical,
			Reason: "SPDX package without name (structural)"},
		{RuleID: "SPDX-EMPTY-PACKAGES", Severity: policy.SeverityHigh,
			Reason: "SPDX SBOM has no packages"},
	}
}

// euCRARules: the EU CRA validator's gaps are operator-supplementable;
// keep them low/medium and ignore on file.
func euCRARules() []SeverityRule {
	return []SeverityRule{
		{RuleID: "EU-CRA-ART13-VULN-HANDLING", Severity: policy.SeverityMedium,
			Reason: "no authoritative vuln handling signal in SBOM"},
		{RuleID: "EU-CRA-ART13-LICENSE", Severity: policy.SeverityLow,
			Reason: "major-framework license metadata missing"},
		{RuleID: "EU-CRA-ART13-LICENSE", ComponentType: model.ComponentTypeFile,
			Severity: policy.SeverityIgnored},
	}
}
