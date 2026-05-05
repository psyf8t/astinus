package pathclassifier

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
)

// Classifier evaluates paths against a fixed set of rules.
//
// Rules are pre-compiled in New for cheap per-path lookup. The
// resulting object is read-only and safe for concurrent Classify
// calls (no mutex needed — the trie nodes and maps are never
// modified after construction).
type Classifier struct {
	rules []Rule

	// Pre-compiled per-pattern-type indexes.
	prefixTrie    *trie
	suffixTrie    *trie
	filenameExact map[string]*Rule

	// Slow-path matchers — applied after the trie/map fast paths.
	// Order matches the rule slice's order so first-match-wins is
	// stable.
	globRules  []*compiledGlob
	regexRules []*compiledRegex
}

type compiledGlob struct {
	rule     *Rule
	patterns []string
}

type compiledRegex struct {
	rule     *Rule
	patterns []*regexp.Regexp
}

// New compiles rules into a Classifier. Returns an error when a rule
// has an unrecognised Pattern.Type, an empty Pattern.Values list, or
// (for PatternRegex) an unparseable regular expression.
//
// Two rules with the same Name are not a New-time error — Merge
// catches that earlier. New copies the rule slice so callers may
// mutate the input afterwards without affecting the classifier.
func New(rules []Rule) (*Classifier, error) {
	if len(rules) == 0 {
		return &Classifier{}, nil
	}

	c := &Classifier{
		rules:         append([]Rule(nil), rules...),
		filenameExact: map[string]*Rule{},
	}
	c.prefixTrie = newTrie()
	c.suffixTrie = newTrie()

	for i := range c.rules {
		r := &c.rules[i]
		if r.Confidence == 0 {
			r.Confidence = 1.0
		}
		if len(r.Pattern.Values) == 0 {
			return nil, fmt.Errorf("rule %q: pattern.values is empty", r.Name)
		}
		if err := c.indexRule(r); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}

	return c, nil
}

// indexRule routes one rule into the appropriate per-type index.
func (c *Classifier) indexRule(r *Rule) error {
	switch r.Pattern.Type {
	case PatternPrefix:
		for _, v := range r.Pattern.Values {
			c.prefixTrie.insert(v, r)
		}
	case PatternSuffix:
		for _, v := range r.Pattern.Values {
			c.suffixTrie.insert(reversedString(v), r)
		}
	case PatternFilenameExact:
		for _, v := range r.Pattern.Values {
			if _, exists := c.filenameExact[v]; !exists {
				c.filenameExact[v] = r
			}
		}
	case PatternGlob:
		for _, v := range r.Pattern.Values {
			if _, err := filepath.Match(v, ""); err != nil {
				return fmt.Errorf("invalid glob %q: %w", v, err)
			}
		}
		c.globRules = append(c.globRules, &compiledGlob{rule: r, patterns: r.Pattern.Values})
	case PatternRegex:
		compiled := make([]*regexp.Regexp, 0, len(r.Pattern.Values))
		for _, v := range r.Pattern.Values {
			re, err := regexp.Compile(v)
			if err != nil {
				return fmt.Errorf("invalid regex %q: %w", v, err)
			}
			compiled = append(compiled, re)
		}
		c.regexRules = append(c.regexRules, &compiledRegex{rule: r, patterns: compiled})
	default:
		return fmt.Errorf("unknown pattern type %q", r.Pattern.Type)
	}
	return nil
}

// Classify returns the Decision for a single path.
//
// Dispatch order (cheapest-first):
//
//  1. filename_exact — O(1) map lookup on the basename.
//  2. prefix — O(L) trie walk where L = path length. Longest match
//     wins (so a specific rule beats a shorter generic one).
//  3. suffix — O(L) trie walk on the reversed path.
//  4. glob — O(N · L) where N = glob rules.
//  5. regex — O(N · regex-cost) where N = regex rules.
//
// Within each dispatch step, rules retain the input order; across
// steps, the first matching step wins. An empty Decision (zero
// Action) means no rule matched — the caller should fall through
// to its native classification.
func (c *Classifier) Classify(filePath string) Decision {
	if filePath == "" {
		return Decision{}
	}
	if r, ok := c.filenameExact[path.Base(filePath)]; ok {
		return decisionFor(r)
	}
	if r := c.matchPrefix(filePath); r != nil {
		return decisionFor(r)
	}
	if r := c.matchSuffix(filePath); r != nil {
		return decisionFor(r)
	}
	if r := c.matchGlob(filePath); r != nil {
		return decisionFor(r)
	}
	if r := c.matchRegex(filePath); r != nil {
		return decisionFor(r)
	}
	return Decision{}
}

func (c *Classifier) matchPrefix(p string) *Rule {
	if c.prefixTrie == nil {
		return nil
	}
	return c.prefixTrie.longestMatch(p)
}

func (c *Classifier) matchSuffix(p string) *Rule {
	if c.suffixTrie == nil {
		return nil
	}
	return c.suffixTrie.longestMatch(reversedString(p))
}

func (c *Classifier) matchGlob(p string) *Rule {
	for _, g := range c.globRules {
		for _, pat := range g.patterns {
			ok, err := filepath.Match(pat, p)
			if err == nil && ok {
				return g.rule
			}
		}
	}
	return nil
}

func (c *Classifier) matchRegex(p string) *Rule {
	for _, rg := range c.regexRules {
		for _, re := range rg.patterns {
			if re.MatchString(p) {
				return rg.rule
			}
		}
	}
	return nil
}

// Rules returns the compiled rule slice. Useful for tests and CLI
// "show me what's loaded" diagnostics. Returns a copy so callers
// cannot mutate the classifier.
func (c *Classifier) Rules() []Rule {
	if len(c.rules) == 0 {
		return nil
	}
	out := make([]Rule, len(c.rules))
	copy(out, c.rules)
	return out
}

func decisionFor(r *Rule) Decision {
	return Decision{
		Action:     r.Action,
		RuleName:   r.Name,
		Reason:     r.Rationale,
		Confidence: r.Confidence,
	}
}
