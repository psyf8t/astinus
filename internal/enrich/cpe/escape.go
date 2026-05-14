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

// NormalizeCPEEncoding converts URL-percent-encoded attribute slots
// in a CPE 2.3 URI into the spec-correct backslash-escape shape.
// Input SBOMs from upstream tools occasionally carry CPEs with
// `%3A`, `%2B`, `%40` etc. (some wrapper layer URL-encoded the
// version field instead of applying the §6.1.2.5 backslash); this
// helper restores the spec-correct form at ingest time so the
// downstream CPE machinery + Astinus's own output stay consistent.
//
// Returns the input unchanged on:
//
//   - Inputs that don't parse as CPE 2.3 (passthrough — let the
//     validator reject if it cares).
//   - Inputs whose slots carry no URL-percent triplets (no work
//     needed; same string returned).
//
// Decoding accepts the operator-facing common subset (%3A, %2B,
// %40, %5C, %20, %2F, %3F, %3D, %26, %23, %25, %5E, %7E, %3B,
// %2C) — anything else passes through unchanged so a Pre-S7 URI
// with `%99` (not a CPE special) lands without mangling.
// S7 Task 1 / ADR-0058 amendment.
func NormalizeCPEEncoding(cpe string) string {
	if !strings.Contains(cpe, "%") {
		return cpe
	}
	parts, ok := splitCPEv23(cpe)
	if !ok {
		return cpe
	}
	changed := false
	for i := 3; i < len(parts); i++ {
		raw := parts[i]
		if raw == "" || raw == "*" || raw == "-" {
			continue
		}
		// URL-decode the slot (best-effort) and re-escape via
		// the spec-correct backslash. The unescape step lets a
		// downstream tool send `1%3A2.75-10%2Bb8` as the version
		// slot; the resulting Astinus-emitted CPE carries
		// `1\:2.75-10\+b8`.
		decoded := percentDecodeCPESlot(raw)
		if decoded == raw {
			continue
		}
		parts[i] = EscapeCPE23Attribute(decoded)
		changed = true
	}
	if !changed {
		return cpe
	}
	return strings.Join(parts, ":")
}

// percentDecodeCPESlot performs a minimal URL-percent decode over
// the subset of triplets that map to CPE 2.3 special characters.
// Returns the input unchanged when no recognised triplet is found.
// We DON'T use net/url.QueryUnescape because that's too aggressive
// (would decode `%99` to `\x99` etc., mangling already-spec-correct
// slots that happen to contain a literal `%`).
func percentDecodeCPESlot(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			triplet := strings.ToUpper(s[i : i+3])
			if r, ok := cpePercentDecodeMap[triplet]; ok {
				b.WriteRune(r)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// cpePercentDecodeMap is the recognised URL-percent triplet → CPE
// 2.3 special-character table. Limited to characters in
// cpe23SpecialChars (plus `%20` → space, which the formatter
// treats as literal). S7 Task 1.
var cpePercentDecodeMap = map[string]rune{
	"%3A": ':',
	"%2B": '+',
	"%40": '@',
	"%5C": '\\',
	"%20": ' ',
	"%2F": '/',
	"%3F": '?',
	"%3D": '=',
	"%26": '&',
	"%23": '#',
	"%25": '%',
	"%5E": '^',
	"%7E": '~',
	"%3B": ';',
	"%2C": ',',
	"%28": '(',
	"%29": ')',
	"%5B": '[',
	"%5D": ']',
	"%7B": '{',
	"%7D": '}',
	"%7C": '|',
	"%60": '`',
	"%21": '!',
	"%22": '"',
	"%24": '$',
	"%27": '\'',
	"%3C": '<',
	"%3E": '>',
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
