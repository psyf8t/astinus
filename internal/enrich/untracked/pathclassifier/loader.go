package pathclassifier

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed rules/default.yaml
var defaultRulesYAML []byte

// supportedRulesVersion is the only `version:` value the loader
// accepts today. Bumped together with the schema.
const supportedRulesVersion = 1

// RulesFile is the on-disk shape of a rules YAML document.
type RulesFile struct {
	// Version is the schema version (currently 1). The loader
	// rejects any other value rather than silently ignoring fields
	// it does not recognise.
	Version int `yaml:"version"`

	// Rules is the ordered rule list. Order within a file decides
	// tie-breaks across pattern types when two rules of the same
	// type would both match (first-in-input-order wins).
	Rules []Rule `yaml:"rules"`
}

// LoadDefault returns the bundled default rule set. Always succeeds
// at runtime — if it fails, that's a build-time bug (the //go:embed
// directive would have already failed) or a malformed default.yaml.
func LoadDefault() ([]Rule, error) {
	return Load(defaultRulesYAML)
}

// Load parses a rules YAML document. Returns an error when the YAML
// is malformed, when version is unsupported, or when two rules in
// the same document share a Name.
func Load(data []byte) ([]Rule, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pathclassifier: empty rules document")
	}
	var rf RulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("pathclassifier: parse YAML: %w", err)
	}
	if rf.Version != supportedRulesVersion {
		return nil, fmt.Errorf("pathclassifier: unsupported rules version %d (want %d)",
			rf.Version, supportedRulesVersion)
	}
	if err := validateRules(rf.Rules); err != nil {
		return nil, err
	}
	return rf.Rules, nil
}

// LoadFromPath reads a rules YAML file from disk.
func LoadFromPath(path string) ([]Rule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied --rules-file is honoured by design
	if err != nil {
		return nil, fmt.Errorf("pathclassifier: read %q: %w", path, err)
	}
	rules, err := Load(data)
	if err != nil {
		return nil, fmt.Errorf("pathclassifier: %s: %w", path, err)
	}
	return rules, nil
}

// Merge layers custom rules on top of defaults. Rules in custom
// override defaults with the same Name; rules in custom whose Name
// does not appear in defaults are appended at the end (so they run
// last among same-pattern-type matches).
//
// The returned slice is freshly allocated; the inputs are not
// modified.
func Merge(defaults, custom []Rule) []Rule {
	if len(custom) == 0 {
		out := make([]Rule, len(defaults))
		copy(out, defaults)
		return out
	}
	overrides := make(map[string]int, len(custom))
	for i := range custom {
		overrides[custom[i].Name] = i
	}

	out := make([]Rule, 0, len(defaults)+len(custom))
	used := make(map[string]bool, len(custom))
	for _, d := range defaults {
		if idx, ok := overrides[d.Name]; ok {
			out = append(out, custom[idx])
			used[d.Name] = true
			continue
		}
		out = append(out, d)
	}
	for _, c := range custom {
		if !used[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// validateRules enforces the document-level invariants that the
// per-rule indexer would otherwise discover later: every rule has a
// Name, every rule has a recognised Action, no two rules share a
// Name within the same file.
func validateRules(rules []Rule) error {
	seen := make(map[string]struct{}, len(rules))
	for i := range rules {
		r := &rules[i]
		if r.Name == "" {
			return fmt.Errorf("pathclassifier: rule #%d has no name", i)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("pathclassifier: duplicate rule name %q", r.Name)
		}
		seen[r.Name] = struct{}{}
		if !knownAction(r.Action) {
			return fmt.Errorf("pathclassifier: rule %q has unknown action %q", r.Name, r.Action)
		}
	}
	return nil
}

func knownAction(a Action) bool {
	switch a {
	case ActionSkip, ActionRedundantUnderArchive, ActionMarkAsNoise, ActionMarkAsRedundant:
		return true
	default:
		return false
	}
}
