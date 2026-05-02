package pathclassifier

// trieNode is one node of a character trie keyed by ASCII byte.
//
// We use map[byte]*trieNode rather than [256]*trieNode because
// production rule sets fan out to ~5 children per node on average,
// so the map is more compact and the lookup overhead is irrelevant
// at our scale (a few hundred patterns, lookups in the µs).
type trieNode struct {
	children map[byte]*trieNode
	// rule is non-nil at nodes that terminate a pattern, with the
	// payload being the rule that owns the pattern. When two patterns
	// terminate at the same node (which a sane rule set should not
	// produce, but YAML happens), the first insertion wins and a
	// second insertion is silently ignored — Load surfaces duplicate
	// Names earlier so this fallback only triggers on truly identical
	// patterns from different rules.
	rule *Rule
}

// trie is a longest-match prefix lookup index.
//
// Insert adds a pattern → rule mapping. LongestMatch walks the trie
// against an input string and returns the rule whose pattern was
// the longest prefix of the input (or nil when no pattern was a
// prefix of the input).
type trie struct {
	root *trieNode
}

func newTrie() *trie {
	return &trie{root: &trieNode{}}
}

// insert adds a pattern → rule mapping. Patterns must be non-empty;
// the empty pattern is silently ignored (it would match every input).
func (t *trie) insert(pattern string, rule *Rule) {
	if pattern == "" {
		return
	}
	node := t.root
	for i := 0; i < len(pattern); i++ {
		if node.children == nil {
			node.children = make(map[byte]*trieNode)
		}
		c := pattern[i]
		child, ok := node.children[c]
		if !ok {
			child = &trieNode{}
			node.children[c] = child
		}
		node = child
	}
	if node.rule == nil {
		node.rule = rule
	}
}

// longestMatch walks the trie against s left-to-right and returns
// the deepest pattern-terminating node's rule, or nil if no pattern
// is a prefix of s.
//
// Walking left-to-right gives "longest match wins" naturally for
// prefix matching: every step deeper either finds a longer matching
// pattern or stops the walk. Callers that need "shortest match wins"
// should iterate the trie differently.
func (t *trie) longestMatch(s string) *Rule {
	node := t.root
	var best *Rule
	if node.rule != nil {
		best = node.rule
	}
	for i := 0; i < len(s); i++ {
		if node.children == nil {
			break
		}
		child, ok := node.children[s[i]]
		if !ok {
			break
		}
		node = child
		if node.rule != nil {
			best = node.rule
		}
	}
	return best
}

// reversedString returns s with its bytes reversed. Used to build
// the suffix trie: insert reversed patterns and walk the input
// reversed too, so suffix matching reduces to the same prefix-trie
// algorithm.
func reversedString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
