package policy

import (
	"path/filepath"
	"strings"
)

// Evaluate runs every rule in the policy against ctx and returns
// the matching decisions in input order. Empty policy / nil ctx
// produce no decisions. ADR-0064.
func (p *Policy) Evaluate(ctx EvalContext) []Decision {
	if p == nil {
		return nil
	}
	var out []Decision
	for _, rule := range p.Rules {
		if matchWhen(&rule.When, ctx) {
			out = append(out, Decision{
				Rule:    rule.ID,
				Action:  rule.Action.Type,
				Message: rule.Action.Message,
			})
		}
	}
	return out
}

// matchWhen recursively evaluates a When predicate. The
// composition operators short-circuit (all → first false wins;
// any → first true wins). Leaves with no constraints match
// trivially (operator-authored catch-all rule); leaves with
// constraints fall through to the matcher helpers.
func matchWhen(w *When, ctx EvalContext) bool {
	if w == nil {
		return true
	}
	if ok, handled := matchWhenComposition(w, ctx); handled {
		return ok
	}
	return matchWhenLeaves(w, ctx)
}

// matchWhenComposition handles the `all` / `any` / `not` operators.
// Returns (result, handled) — handled=false means none of the
// composition operators applied and the caller should fall
// through to the leaf matchers.
func matchWhenComposition(w *When, ctx EvalContext) (bool, bool) {
	switch {
	case len(w.All) > 0:
		for i := range w.All {
			if !matchWhen(&w.All[i], ctx) {
				return false, true
			}
		}
		return true, true
	case len(w.Any) > 0:
		for i := range w.Any {
			if matchWhen(&w.Any[i], ctx) {
				return true, true
			}
		}
		return false, true
	case w.Not != nil:
		return !matchWhen(w.Not, ctx), true
	}
	return false, false
}

// matchWhenLeaves handles the `component` and `finding` leaf
// matchers. Both must pass; an empty leaf matches trivially.
func matchWhenLeaves(w *When, ctx EvalContext) bool {
	if w.Component != nil && !matchComponent(w.Component, ctx.Component) {
		return false
	}
	if w.Finding != nil {
		if ctx.Finding == nil {
			return false
		}
		if !matchFinding(w.Finding, ctx.Finding) {
			return false
		}
	}
	return true
}

// matchComponent checks the supplied matchers against the
// component under evaluation. A nil component fails any
// non-empty matcher; this is the deliberate handling for
// finding-only rules where the gate didn't surface a matching
// component (e.g. SBOM-level NTIA finding with empty Component).
func matchComponent(m *ComponentMatcher, c *Component) bool {
	if m == nil {
		return true
	}
	if c == nil {
		return false
	}
	if m.PURLMatches != "" && !globMatch(m.PURLMatches, c.PURL) {
		return false
	}
	if m.Ecosystem != "" && !equalEcosystem(m.Ecosystem, c.PURL) {
		return false
	}
	if m.VersionBelow != "" && c.Version != "" {
		if c.Version >= m.VersionBelow {
			return false
		}
	}
	if m.HasProperty != nil {
		if c.Properties == nil {
			return false
		}
		got, ok := c.Properties[m.HasProperty.Name]
		if !ok || got != m.HasProperty.Value {
			return false
		}
	}
	return true
}

// matchFinding checks the supplied matchers against the finding
// under evaluation. Nil matcher trivially matches; nil finding
// trivially fails any non-empty matcher.
func matchFinding(m *FindingMatcher, f *Finding) bool {
	if m == nil {
		return true
	}
	if f == nil {
		return false
	}
	if m.IDPrefix != "" && !strings.HasPrefix(f.RuleID, m.IDPrefix) {
		return false
	}
	if m.Severity != "" {
		if !strings.EqualFold(f.Severity.String(), m.Severity) {
			return false
		}
	}
	return true
}

// globMatch reports whether pattern matches s. The implementation
// uses Go's filepath.Match semantics (POSIX-style): `*` matches any
// sequence of non-separator characters; `?` matches a single
// non-separator character; bracket character classes work as
// expected. Returns false on any error from the matcher (malformed
// pattern = no match, not a panic). The policy framework
// validates pattern syntax at LoadFile time so production matches
// never see malformed input.
func globMatch(pattern, s string) bool {
	ok, err := filepath.Match(pattern, s)
	if err != nil {
		return false
	}
	return ok
}

// equalEcosystem compares ecosystem string against the PURL's
// type segment (the bit between `pkg:` and the first `/`).
// Case-insensitive. Empty PURL returns false; malformed PURL
// returns false.
func equalEcosystem(eco, purl string) bool {
	if purl == "" {
		return false
	}
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return false
	}
	rest := purl[len(prefix):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return false
	}
	return strings.EqualFold(rest[:slash], eco)
}
