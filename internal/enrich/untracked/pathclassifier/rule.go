package pathclassifier

// Action is what the untracked enricher should do with a path that
// matched a rule.
type Action string

// Recognised actions. Empty Action ("") means "no rule matched";
// callers should fall through to the existing classification path.
const (
	// ActionSkip removes the file from consideration entirely — no
	// component is added, no matcher lookup is queued.
	ActionSkip Action = "skip"

	// ActionRedundantUnderArchive marks a file that sits inside an
	// archive whose parent component already covers it. Today the
	// untracked enricher treats this the same as Skip (the file is
	// not added). Task 3 (clustering) will use this to attribute the
	// file to its parent archive component. Marking it now lets
	// rules express the intent stably.
	ActionRedundantUnderArchive Action = "redundant_under_archive"

	// ActionMarkAsNoise records the file but tags its category as
	// noise so consumers downstream can filter / downplay it.
	ActionMarkAsNoise Action = "mark_as_noise"

	// ActionMarkAsRedundant records the file but tags its category
	// as redundant.
	ActionMarkAsRedundant Action = "mark_as_redundant"
)

// PatternType selects the matcher used for a rule's Values.
type PatternType string

// Recognised pattern types.
const (
	// PatternPrefix — path starts with one of Values.
	PatternPrefix PatternType = "prefix"
	// PatternSuffix — path ends with one of Values.
	PatternSuffix PatternType = "suffix"
	// PatternFilenameExact — path's basename equals one of Values.
	PatternFilenameExact PatternType = "filename_exact"
	// PatternGlob — path matches Values via path/filepath.Match.
	PatternGlob PatternType = "glob"
	// PatternRegex — path matches Values as Go regexp (RE2).
	PatternRegex PatternType = "regex"
)

// Pattern is the matcher specification on a Rule.
type Pattern struct {
	Type   PatternType `yaml:"type"`
	Values []string    `yaml:"values"`
}

// Rule is one declarative classification entry.
//
// The YAML schema is documented in `internal/enrich/untracked/rules/README.md`
// and is committed to as v1 of the rules file format.
type Rule struct {
	// Name is the rule identifier. Two rules with the same Name in
	// the same file are a load-time error; in Merge, a custom rule
	// with the same Name overrides the default.
	Name string `yaml:"name"`

	// Description is human-readable; not consumed by the classifier.
	Description string `yaml:"description"`

	// Action is what to do when Pattern matches.
	Action Action `yaml:"action"`

	// Pattern is the matcher.
	Pattern Pattern `yaml:"pattern"`

	// Rationale is the operator-facing explanation surfaced in
	// Decision.Reason for debug / audit logs.
	Rationale string `yaml:"rationale"`

	// Confidence is the rule's confidence in its decision. Defaults
	// to 1.0 when omitted. Reserved for future weighted classifiers
	// — today the first-match-wins chain ignores it beyond passing
	// the value through to Decision.Confidence.
	Confidence float64 `yaml:"confidence,omitempty"`

	// AppliesTo restricts the rule to a subset of file categories
	// (executable / library / script / …). Empty means "all
	// categories". Today the classifier is invoked before category
	// classification so AppliesTo is purely advisory; reserved.
	AppliesTo []string `yaml:"applies_to,omitempty"`
}

// Decision is the classifier's per-path verdict.
//
// An empty Action means "no rule matched"; the caller should run its
// own fallback (the existing magic-byte classifier).
type Decision struct {
	Action     Action
	RuleName   string
	Reason     string
	Confidence float64
}
