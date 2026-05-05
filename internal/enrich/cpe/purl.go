package cpe

import (
	"fmt"
	"net/url"
	"strings"
)

// PURL is the parsed form of a Package URL
// (https://github.com/package-url/purl-spec).
//
// Format: `pkg:<type>/<namespace?>/<name>@<version>?qualifiers#subpath`.
type PURL struct {
	Type       string            // "npm", "pypi", "maven", …
	Namespace  string            // "" or "org.apache.logging.log4j"
	Name       string            // "express"
	Version    string            // "" or "4.18.2"
	Qualifiers map[string]string // "" → empty map
	Subpath    string
}

// ParsePURL is a small PURL parser. It does not implement every
// percent-encoding rule of the spec but handles the shapes Astinus
// actually encounters in real-world SBOMs.
//
// Returns an error for empty input or missing `pkg:` prefix.
func ParsePURL(s string) (PURL, error) {
	if s == "" {
		return PURL{}, fmt.Errorf("purl: empty")
	}
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return PURL{}, fmt.Errorf("purl: missing pkg: prefix in %q", s)
	}

	out := PURL{Qualifiers: map[string]string{}}

	// Subpath (after #).
	if idx := strings.LastIndex(rest, "#"); idx >= 0 {
		out.Subpath = rest[idx+1:]
		rest = rest[:idx]
	}
	// Qualifiers (after ?).
	if idx := strings.LastIndex(rest, "?"); idx >= 0 {
		q, err := url.ParseQuery(rest[idx+1:])
		if err == nil {
			for k, v := range q {
				if len(v) > 0 {
					out.Qualifiers[k] = v[0]
				}
			}
		}
		rest = rest[:idx]
	}
	// Version (after the last @, but @ may also appear in version-tail
	// of namespace/name segments — purl-spec defines version as
	// everything after the FIRST @ of the path-after-type, so split on
	// the leftmost @).
	if idx := strings.Index(rest, "@"); idx >= 0 {
		out.Version = rest[idx+1:]
		rest = rest[:idx]
	}

	// Type / namespace / name.
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return PURL{}, fmt.Errorf("purl: missing type/name separator in %q", s)
	}
	out.Type = strings.ToLower(rest[:idx])
	rest = rest[idx+1:]

	// Everything after the type is "namespace/.../name". Last segment
	// is the name; the rest is the namespace (joined back with "/").
	segs := strings.Split(rest, "/")
	if len(segs) == 0 || segs[len(segs)-1] == "" {
		return PURL{}, fmt.Errorf("purl: missing name in %q", s)
	}
	out.Name = decodeSegment(segs[len(segs)-1])
	if len(segs) > 1 {
		ns := make([]string, 0, len(segs)-1)
		for _, seg := range segs[:len(segs)-1] {
			ns = append(ns, decodeSegment(seg))
		}
		out.Namespace = strings.Join(ns, "/")
	}
	return out, nil
}

// decodeSegment percent-decodes one path segment of a PURL. Errors
// are tolerated — we keep the original on failure to avoid silently
// dropping data.
func decodeSegment(s string) string {
	if dec, err := url.PathUnescape(s); err == nil {
		return dec
	}
	return s
}

// String reconstructs a canonical PURL string. Useful for round-trip
// tests and for emitting debug logs.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		b.WriteByte('/')
		b.WriteString(p.Namespace)
	}
	b.WriteByte('/')
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}
	return b.String()
}
