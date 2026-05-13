package policy

// Sprint 6 Task 7 — operator-supplied YAML policy framework.
//
// The compliance enricher already emits typed Findings (rule ID +
// severity + component). The policy framework adds an
// operator-tunable layer ON TOP of those findings:
//
//   - Allow rules suppress findings the operator has explicitly
//     accepted (e.g. "criticals on base-image components are
//     vendor responsibility").
//   - Deny rules promote a policy decision into a synthetic
//     POLICY-<rule-id> finding that contributes to the gate.
//   - Warn rules stamp SBOM metadata for downstream review
//     without affecting the gate.
//
// The schema is YAML for operator authoring + auditing.
// `internal/policy/loader.go` enforces strict decoding (unknown
// keys → error) so a typo doesn't silently disable a rule.
//
// Distinct from VEX (S6 Task 6 / ADR-0063):
//
//   - VEX = "this specific CVE-on-this-product doesn't apply".
//   - Policy = "this class of components/findings should be
//     handled this way."
//
// Gate composition order: VEX first (per-vuln) → policy
// (per-rule) → default `--fail-on` floor. ADR-0064.

// Policy is the top-level YAML document operators author. Multiple
// policies passed via repeated `--policy <file>` flag stack in
// invocation order; the gate evaluates them in sequence and applies
// decisions on a first-match-per-finding basis. S6 Task 7.
type Policy struct {
	Version     string `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Rules       []Rule `yaml:"rules"`

	// SourcePath records where the policy was loaded from so
	// Decisions can reference back. Populated by the loader; not
	// part of the YAML schema.
	SourcePath string `yaml:"-"`
}

// Rule pairs a When predicate with an Action the policy framework
// applies when the predicate matches the (component, finding)
// pair under evaluation. The Rule ID is operator-controlled and
// surfaces on the SBOM metadata stamp (`astinus:policy:hit:<id>`).
type Rule struct {
	ID     string `yaml:"id"`
	When   When   `yaml:"when"`
	Action Action `yaml:"action"`
}

// When is the rule predicate. The composition operators
// `all` / `any` / `not` permit arbitrary trees of nested
// conditions; the leaf forms `component` and `finding` carry
// the actual matchers. Leaving every field zero means "match
// everything" — operators authoring catch-all rules use it
// deliberately. ADR-0064.
type When struct {
	Component *ComponentMatcher `yaml:"component,omitempty"`
	Finding   *FindingMatcher   `yaml:"finding,omitempty"`
	All       []When            `yaml:"all,omitempty"`
	Any       []When            `yaml:"any,omitempty"`
	Not       *When             `yaml:"not,omitempty"`
}

// ComponentMatcher filters by attributes of the SBOM component
// under evaluation. Empty fields don't constrain.
type ComponentMatcher struct {
	// PURLMatches is a glob pattern matched against the
	// component's PURL. `*` matches any sequence of characters
	// EXCEPT slashes; `**` matches across slash boundaries. The
	// match is anchored to the full PURL string. Example:
	// `pkg:apk/alpine/*` matches every alpine apk component.
	PURLMatches string `yaml:"purl_matches,omitempty"`

	// Ecosystem matches the PURL type segment exactly (npm,
	// maven, pypi, golang, deb, apk, …). Case-insensitive.
	Ecosystem string `yaml:"ecosystem,omitempty"`

	// VersionBelow is a string-compared version ceiling (the
	// component's Version field must compare less than this
	// value lexically). NOT a full SemVer comparator — covers
	// the common `version: 2.0.0` baseline case; complex
	// version-range matching is Sprint 8 follow-up. Empty =
	// no version constraint.
	VersionBelow string `yaml:"version_below,omitempty"`

	// HasProperty requires the component to carry a property
	// `<Name> = <Value>` exactly.
	HasProperty *PropertyMatcher `yaml:"has_property,omitempty"`
}

// PropertyMatcher pins a single property on a component.
type PropertyMatcher struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// FindingMatcher filters by attributes of the compliance finding
// under evaluation. The policy framework uses the existing
// `policy.Finding` type (the compliance enricher's output) — no
// separate vulnerability model. Empty fields don't constrain.
type FindingMatcher struct {
	// IDPrefix matches when the finding's RuleID starts with
	// this string. Common values: `CVE-` (CVE findings),
	// `NTIA-` (NTIA validators), `EU-CRA-` (EU CRA rules).
	IDPrefix string `yaml:"id_prefix,omitempty"`

	// Severity matches exactly. Values: `critical`, `high`,
	// `medium`, `low`, `info`. Case-insensitive.
	Severity string `yaml:"severity,omitempty"`
}

// Action is the operator-supplied directive the rule emits when
// its When predicate matches. ADR-0064 ships three of the four
// possible types — `remap_severity` is deferred to Sprint 8.
type Action struct {
	Type    ActionType `yaml:"type"`
	Message string     `yaml:"message,omitempty"`
}

// ActionType enumerates the operations a rule may apply.
type ActionType string

// Recognised action types. ActionDeny promotes the decision into
// a synthetic POLICY-<rule-id> finding the gate counts; ActionAllow
// suppresses matching findings the gate would otherwise count;
// ActionWarn stamps metadata only (no gate effect). The CLI rejects
// any other value at load time.
const (
	ActionDeny  ActionType = "deny"
	ActionAllow ActionType = "allow"
	ActionWarn  ActionType = "warn"
)

// IsKnown reports whether the action type is one of the recognised
// values; helps the loader produce a clean error message.
func (a ActionType) IsKnown() bool {
	switch a {
	case ActionDeny, ActionAllow, ActionWarn:
		return true
	}
	return false
}

// Decision is the operator-visible record of a rule matching an
// EvalContext. The gate aggregates Decisions across all findings +
// stamps SBOM metadata; CI pipelines branch on the action surface.
type Decision struct {
	Rule    string
	Action  ActionType
	Message string
	Source  string // policy file path
}

// EvalContext carries the inputs to a single rule evaluation. The
// Finding pointer may be nil for component-only rules (the rule's
// When predicate must then omit `finding` or its leaves; otherwise
// matchWhen returns false).
type EvalContext struct {
	Component *Component // SBOM component being evaluated; nil-safe in matchers
	Finding   *Finding   // Compliance finding; nil for component-only rules
}

// Component is a tiny shim around model.Component the policy
// framework reads. We re-declare the fields we touch so the
// policy package can be unit-tested without importing the larger
// sbom/model graph (and so future renames in model don't ripple
// through the policy schema). The CLI's gate adapter projects
// model.Component → policy.Component before calling Evaluate.
type Component struct {
	BOMRef     string
	Name       string
	Version    string
	PURL       string
	Properties map[string]string
}
