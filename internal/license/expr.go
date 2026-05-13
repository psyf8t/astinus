// Package license implements SPDX-based allow/deny gating for the
// compliance evaluation step. The shape is deliberately narrow:
//
//   - `--license-allow MIT --license-allow Apache-2.0` means
//     "every component must declare a license that resolves to one
//     of these SPDX IDs".
//   - `--license-deny GPL-3.0-only --license-deny AGPL-3.0-only`
//     means "any component declaring one of these fails".
//   - `--license-require-known` toggles whether unknown /
//     unparseable / empty license fields fail the gate (default:
//     pass with a WARN).
//
// Deny takes precedence over allow: a `MIT OR GPL-3.0-only` dual
// license still fails when GPL-3.0-only is in the deny list, even
// though MIT is in the allow list. This matches the conservative
// reading every legal-counsel review of OSS license policy lands
// on: "if it CAN be released as GPL, treat it as GPL."
//
// S6 Task 8 / ADR-0065.
package license

import (
	"fmt"
	"strings"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Decision is the operator-visible record of evaluating one
// component against the license gate. Aggregated into the
// LicenseResult the CLI surfaces both as SBOM metadata and as
// per-violation log lines.
type Decision struct {
	Component *model.Component
	// SPDXIDs is the set of identifiers extracted from the
	// component's Licenses entries (Component.Licenses).
	// Multiple entries yield a union; OR/AND expressions are
	// flattened.
	SPDXIDs []string
	// Allowed records the matching SPDX IDs from the allow
	// list (when one was passed). Empty when allow wasn't set.
	Allowed []string
	// Denied records the matching SPDX IDs from the deny list.
	Denied []string
	// Unknown records SPDX-shaped tokens we couldn't recognise
	// (parser fallback) or empty-license rows.
	Unknown  []string
	Decision Action
	Reason   string
}

// Action enumerates the per-component gating outcomes.
type Action string

// Recognised actions. ActionDeny fails the component through the
// gate (the CLI promotes it to a LICENSE-<...> synthetic finding);
// ActionUnknown surfaces a WARN but doesn't block; ActionAllow is
// the pass-through case.
const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionUnknown Action = "unknown"
)

// Options carries the operator-supplied gate configuration. Zero
// value (empty slices + RequireKnown=false) disables the gate; the
// CLI short-circuits accordingly.
type Options struct {
	Allow        []string
	Deny         []string
	RequireKnown bool
}

// IsEnabled reports whether any of the three gate inputs were
// configured. Used by the CLI to short-circuit the evaluation when
// the operator passed no license flags.
func (o Options) IsEnabled() bool {
	return len(o.Allow) > 0 || len(o.Deny) > 0 || o.RequireKnown
}

// EvaluateComponent runs the license gate against a single
// component. The decision precedence (highest first):
//
//  1. Any extracted SPDX ID in `deny` → ActionDeny.
//  2. `allow` non-empty AND no extracted SPDX ID in `allow` →
//     ActionDeny.
//  3. RequireKnown AND no parseable SPDX IDs → ActionDeny.
//  4. No SPDX IDs AND not RequireKnown → ActionUnknown.
//  5. Otherwise → ActionAllow.
//
// ADR-0065.
func EvaluateComponent(c *model.Component, opts Options) Decision {
	dec := Decision{Component: c}

	exprs := collectExpressions(c)
	if len(exprs) == 0 {
		dec.Reason = "no license declared"
		if opts.RequireKnown {
			dec.Decision = ActionDeny
		} else {
			dec.Decision = ActionUnknown
		}
		return dec
	}

	for _, e := range exprs {
		ids, ok := extractSPDXIDs(e)
		if !ok {
			dec.Unknown = append(dec.Unknown, e)
			continue
		}
		dec.SPDXIDs = appendUnique(dec.SPDXIDs, ids...)
	}

	denied := intersectFold(dec.SPDXIDs, opts.Deny)
	if len(denied) > 0 {
		dec.Denied = denied
		dec.Decision = ActionDeny
		dec.Reason = fmt.Sprintf("license %s matches --license-deny",
			strings.Join(denied, ","))
		return dec
	}

	if len(opts.Allow) > 0 {
		allowed := intersectFold(dec.SPDXIDs, opts.Allow)
		if len(allowed) == 0 {
			dec.Decision = ActionDeny
			dec.Reason = fmt.Sprintf("license %s not in --license-allow (%s)",
				strings.Join(dec.SPDXIDs, ","),
				strings.Join(opts.Allow, ","))
			return dec
		}
		dec.Allowed = allowed
	}

	if len(dec.Unknown) > 0 && opts.RequireKnown {
		dec.Decision = ActionDeny
		dec.Reason = fmt.Sprintf("unparseable license expression(s): %s",
			strings.Join(dec.Unknown, "; "))
		return dec
	}
	if len(dec.Unknown) > 0 {
		dec.Decision = ActionUnknown
		dec.Reason = fmt.Sprintf("unparseable license expression(s): %s",
			strings.Join(dec.Unknown, "; "))
		return dec
	}
	dec.Decision = ActionAllow
	return dec
}

// collectExpressions returns every non-empty license string from
// a component — both structured SPDX IDs and free-form expressions
// land in the same slice for downstream extraction.
func collectExpressions(c *model.Component) []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, l := range c.Licenses {
		if l.SPDXID != "" {
			out = append(out, l.SPDXID)
		}
		if l.Expression != "" {
			out = append(out, l.Expression)
		}
	}
	return out
}

// extractSPDXIDs parses an SPDX expression and returns every
// identifier referenced. The parser is intentionally permissive:
// strips parens, splits on `OR`/`AND` (case-insensitive), trims
// whitespace, ignores `WITH <exception>` suffixes. Returns
// (ids, false) when the expression contains a token that doesn't
// look like an SPDX identifier (`[A-Za-z][A-Za-z0-9.+\-]*`).
//
// Trade-off vs a third-party library: we avoid adding
// github.com/github/go-spdx (~1 MB transitive) for one parsing
// function. The library handles edge cases (the SPDX spec's full
// grammar including `+` suffix licenses) more rigorously; if real-
// world inputs surface a gap, the implementation can move to the
// library without changing the operator contract. ADR-0065.
func extractSPDXIDs(expr string) ([]string, bool) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return nil, false
	}
	// Replace parens with spaces and tokenise.
	s = strings.ReplaceAll(s, "(", " ")
	s = strings.ReplaceAll(s, ")", " ")
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(tokens))
	skipNext := false
	for _, tok := range tokens {
		if skipNext {
			skipNext = false
			continue
		}
		switch strings.ToUpper(tok) {
		case "OR", "AND":
			continue
		case "WITH":
			// Next token is an exception modifier — skip it; the
			// underlying license already landed.
			skipNext = true
			continue
		}
		if !isSPDXIdentifier(tok) {
			return nil, false
		}
		out = append(out, tok)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// isSPDXIdentifier reports whether tok matches the SPDX short-id
// grammar (start with a letter, allow letters / digits / `.` /
// `+` / `-`). Tighter than SPDX's full grammar but covers every
// identifier on the SPDX license list as of 2026-05.
func isSPDXIdentifier(tok string) bool {
	if tok == "" {
		return false
	}
	for i, r := range tok {
		if i == 0 && !isASCIILetter(r) {
			return false
		}
		if !isSPDXChar(r) {
			return false
		}
	}
	return true
}

// isASCIILetter reports whether r is in [A-Za-z].
func isASCIILetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// isSPDXChar reports whether r is permitted inside an SPDX
// identifier (letter, digit, or one of `.`/`+`/`-`).
func isSPDXChar(r rune) bool {
	if isASCIILetter(r) {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	return r == '.' || r == '+' || r == '-'
}

// intersectFold returns the elements of a that appear in b under
// case-insensitive comparison. Order preserved from a; duplicates
// deduplicated. SPDX identifiers are documented case-insensitive
// in practice (`mit` ≡ `MIT`), so the operator who types
// `--license-deny mit` shouldn't miss a component declaring `MIT`.
func intersectFold(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	bSet := make(map[string]bool, len(b))
	for _, e := range b {
		bSet[strings.ToLower(strings.TrimSpace(e))] = true
	}
	seen := make(map[string]bool, len(a))
	out := make([]string, 0, len(a))
	for _, e := range a {
		key := strings.ToLower(strings.TrimSpace(e))
		if !bSet[key] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

// appendUnique appends values to dst, skipping any value already
// present (case-sensitive — caller preserves the casing of the
// first occurrence).
func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, e := range dst {
		seen[e] = true
	}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			dst = append(dst, v)
		}
	}
	return dst
}
