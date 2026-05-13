package cpe

import "strings"

// CPE 2.3 special characters per NIST IR 7695 §6.1.2.5.
// In Formatted String Binding, these MUST be backslash-escaped when
// they appear inside an attribute value (vendor, product, version,
// update, edition, language, sw_edition, target_sw, target_hw,
// other). Spaces are NOT in this set — they get replaced with `_`
// at the binding boundary, but that convention is upstream of this
// helper; we treat space as a literal character.
//
// Source: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
// §6.1.2.5 ("Formatted String Binding") + Table 6-1.
var cpe23SpecialChars = map[rune]struct{}{
	'!':  {},
	'"':  {},
	'#':  {},
	'$':  {},
	'%':  {},
	'&':  {},
	'\'': {},
	'(':  {},
	')':  {},
	'+':  {},
	',':  {},
	'/':  {},
	':':  {},
	';':  {},
	'<':  {},
	'=':  {},
	'>':  {},
	'?':  {},
	'@':  {},
	'[':  {},
	'\\': {},
	']':  {},
	'^':  {},
	'`':  {},
	'{':  {},
	'|':  {},
	'}':  {},
	'~':  {},
}

// EscapeCPE23Attribute backslash-escapes special characters in a
// CPE 2.3 attribute value. Returns the wildcard sentinel `*` for an
// empty input (matches Syft's convention so consumers don't see
// empty slots inside the URI) and preserves the non-applicable
// sentinel `-` unchanged. ADR-0058.
//
// Idempotency note: applying EscapeCPE23Attribute twice on a value
// that already carries `\` escapes doubles the backslashes. Callers
// MUST pass the human-readable form (e.g. `1:2.75-10+b8`), not the
// escaped form. Re-escaping is the caller's responsibility to avoid.
func EscapeCPE23Attribute(s string) string {
	switch s {
	case "", "*":
		return "*"
	case "-":
		return "-"
	}

	var b strings.Builder
	b.Grow(len(s) + 4) // typical: 0-4 escapes; one alloc

	for _, r := range s {
		if _, special := cpe23SpecialChars[r]; special {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// UnescapeCPE23Attribute reverses EscapeCPE23Attribute. Used when
// parsing CPE strings back to component fields. Preserves the
// wildcard / non-applicable sentinels unchanged. ADR-0058.
func UnescapeCPE23Attribute(s string) string {
	if s == "" || s == "*" || s == "-" {
		return s
	}
	if !strings.ContainsRune(s, '\\') {
		return s // fast path: nothing to unescape
	}
	var b strings.Builder
	b.Grow(len(s))
	escape := false
	for _, r := range s {
		if escape {
			b.WriteRune(r)
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			continue
		}
		b.WriteRune(r)
	}
	// Trailing single backslash with nothing after it — preserve as
	// literal so we don't silently drop data.
	if escape {
		b.WriteByte('\\')
	}
	return b.String()
}

// splitCPEv23 splits the colon-separated attribute slots of a CPE 2.3
// URI, honouring backslash-escaped colons inside slot values. Returns
// the 13-element slice [scheme, version-tag, part, vendor, product,
// version, update, edition, language, sw_edition, target_sw,
// target_hw, other] when the input is well-formed; (nil, false)
// otherwise. Each returned slot is the raw (still-escaped) substring;
// callers run UnescapeCPE23Attribute before consuming the value.
// ADR-0058.
func splitCPEv23(s string) ([]string, bool) {
	out := make([]string, 0, 13)
	var current strings.Builder
	escape := false

	for _, r := range s {
		if escape {
			current.WriteRune(r)
			escape = false
			continue
		}
		if r == '\\' {
			current.WriteByte('\\')
			escape = true
			continue
		}
		if r == ':' {
			out = append(out, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	out = append(out, current.String())
	if escape || len(out) != 13 {
		return nil, false
	}
	return out, true
}
