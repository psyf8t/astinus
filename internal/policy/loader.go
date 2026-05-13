package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadFile reads + parses + validates a policy YAML at path.
// Strict decoder — unknown fields error rather than silently
// drop. Returns a non-nil error AND a nil policy on any failure.
// ADR-0064.
func LoadFile(path string) (*Policy, error) {
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true) // unknown keys → error
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy: validate %s: %w", path, err)
	}
	// Stamp source path on every rule so Decision.Source can
	// reach back to the file. We pre-allocate Source via the
	// loader because rules don't carry the file path natively.
	p.SourcePath = path
	for i := range p.Rules {
		if p.Rules[i].ID == "" {
			p.Rules[i].ID = fmt.Sprintf("%s:rule-%d", filepath.Base(path), i)
		}
	}
	return &p, nil
}

// LoadAll reads every path in files via LoadFile and returns the
// composed slice. Loading STOPS on the first error — operators
// who pass --policy expect early failure on a malformed file
// rather than silent skip.
func LoadAll(files []string) ([]*Policy, error) {
	out := make([]*Policy, 0, len(files))
	for _, path := range files {
		p, err := LoadFile(path)
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Validate runs schema-level checks on a freshly-decoded policy.
// Failed validation returns an error WITH the rule index / ID so
// the operator can find the offending entry. ADR-0064.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("nil policy")
	}
	if p.Version != "1" {
		return fmt.Errorf("unsupported version %q (want \"1\")", p.Version)
	}
	if p.Name == "" {
		return fmt.Errorf("missing name")
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID != "" && seen[r.ID] {
			return fmt.Errorf("rules[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		if !r.Action.Type.IsKnown() {
			return fmt.Errorf("rules[%s]: unknown action type %q (want deny/allow/warn)",
				ruleLabel(r, i), r.Action.Type)
		}
		if err := validateWhen(&r.When, ruleLabel(r, i)); err != nil {
			return err
		}
	}
	return nil
}

// validateWhen recursively checks a When for structural problems
// (a node with no leaves AND no composition operators is a
// catch-all by design, NOT an error). Component / Finding leaf
// matchers must be syntactically sane — globMatch validation
// happens here so a malformed pattern surfaces at LoadFile time,
// not at Evaluate.
func validateWhen(w *When, ruleLabel string) error {
	if w == nil {
		return nil
	}
	if w.Component != nil && w.Component.PURLMatches != "" {
		if _, err := filepath.Match(w.Component.PURLMatches, ""); err != nil {
			return fmt.Errorf("rules[%s]: malformed purl_matches %q: %w",
				ruleLabel, w.Component.PURLMatches, err)
		}
	}
	for i := range w.All {
		if err := validateWhen(&w.All[i], ruleLabel); err != nil {
			return err
		}
	}
	for i := range w.Any {
		if err := validateWhen(&w.Any[i], ruleLabel); err != nil {
			return err
		}
	}
	if w.Not != nil {
		return validateWhen(w.Not, ruleLabel)
	}
	return nil
}

// ruleLabel renders a rule's identifier for error messages. Uses
// the explicit ID when set; otherwise the index.
func ruleLabel(r *Rule, idx int) string {
	if r.ID != "" {
		return r.ID
	}
	return fmt.Sprintf("rules[%d]", idx)
}
