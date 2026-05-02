// Package pathclassifier classifies image filesystem paths against a
// declarative rule set so the untracked enricher can decide whether
// a path should be skipped, marked as noise / redundant, or processed
// normally.
//
// # Why this exists
//
// The Hardening Sprint #1 work moved noise filtering from a hardcoded
// catalog in classifier.go into a slightly less hardcoded one (filter.go),
// but the rules are still scattered across Go literals and changing them
// requires a code change + release. Production deployments need to ship
// per-environment overrides — internal corporate paths, vendor-specific
// junk directories, bespoke compliance categories — without rebuilding
// Astinus.
//
// # Design
//
// Rules are loaded from YAML (a bundled `default.yaml` plus an optional
// `--rules-file` override). Each rule has one of five Pattern types:
//
//   - prefix         — path starts with one of Values (tries).
//   - suffix         — path ends with one of Values (tries).
//   - filename_exact — path's basename equals one of Values (map lookup).
//   - glob           — path matches `path/filepath.Match` syntax.
//   - regex          — path matches a Go regexp.
//
// Classify dispatches by pattern type cheapest-first
// (filename_exact → prefix → suffix → glob → regex). The first
// rule that matches wins.
//
// # Why a trie instead of Aho-Corasick
//
// Aho-Corasick matches patterns anywhere in the input — for prefix /
// suffix anchored matching it does extra work then forces the caller
// to filter false positives by position. A simple character trie is
// the right data structure for anchored matching: O(path-length) per
// lookup, no positional filtering, no external dependency. The trie
// also gives us "longest match wins" naturally — useful when both a
// generic and a specific rule share a prefix.
//
// # What the classifier does NOT do
//
// It does not look at file contents (the magic-byte classification
// in classifier.go remains the authority on file kind). It does not
// invoke I/O. It is read-only with respect to the rule set after
// New().
package pathclassifier
