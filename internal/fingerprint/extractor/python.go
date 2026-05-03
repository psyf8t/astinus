package extractor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// PythonExtractor recovers PyPI identity from a wheel's
// `*.dist-info/METADATA` file (PEP 566 / RFC 822 format).
//
// It complements the package-level cluster anchor extractor (PRSD
// Task 3) — clustering picks up the whole `<name>-<ver>.dist-info/`
// + source-tree pair and emits one Component for the package; this
// extractor catches METADATA files that aren't inside a cluster
// (rare; e.g. an operator handed Astinus a partial filesystem).
type PythonExtractor struct{}

// Name implements Extractor.
func (*PythonExtractor) Name() string { return "python" }

// Confidence — METADATA is the authoritative source the wheel
// installer reads; same precision tier as Go buildinfo / Rust
// auditable.
func (*PythonExtractor) Confidence() float64 { return 0.95 }

// Match accepts only paths whose basename is `METADATA` AND whose
// parent directory ends in `.dist-info`. The bare `METADATA`
// basename also appears in unrelated contexts (Java META-INF,
// arbitrary application config); the dist-info constraint avoids
// false positives.
func (*PythonExtractor) Match(_ context.Context, file File) bool {
	if basename(file.Path) != "METADATA" {
		return false
	}
	dir := dirOf(file.Path)
	return strings.HasSuffix(dir, ".dist-info")
}

// Extract parses Name + Version + Summary + Author + License from
// the RFC 822 header block.
//
// Returns (empty, nil) when METADATA is missing the Name header
// (very rare; would mean the wheel is corrupt).
func (*PythonExtractor) Extract(_ context.Context, file File) (Identity, error) {
	headers := parseRFC822Headers(file.Body)
	name := headers["Name"]
	if name == "" {
		return Identity{}, nil
	}
	version := headers["Version"]
	id := Identity{
		Name:       name,
		Version:    version,
		Vendor:     headers["Author"],
		PURL:       purlPyPI(name, version),
		Properties: map[string]string{},
	}
	if v := headers["Summary"]; v != "" {
		id.Properties["python.summary"] = v
	}
	if v := headers["License"]; v != "" {
		id.Properties["python.license"] = v
	}
	if v := headers["Home-page"]; v != "" {
		id.Properties["python.home-page"] = v
	}
	if v := headers["Requires-Python"]; v != "" {
		id.Properties["python.requires"] = v
	}
	return id, nil
}

// pythonHeaderMaxLines caps how many lines we scan before giving
// up — METADATA's header block ends at the first blank line; the
// description body that follows can be long. We don't need it.
const pythonHeaderMaxLines = 1000

// parseRFC822Headers reads a METADATA-shaped header block: lines of
// `Key: value` until the first blank line. Continuation lines start
// with whitespace and append to the previous value (METADATA rarely
// uses them but PEP 566 allows it).
func parseRFC822Headers(body []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var lastKey string
	lines := 0
	for sc.Scan() {
		lines++
		if lines > pythonHeaderMaxLines {
			break
		}
		line := sc.Text()
		if line == "" {
			break // header section ends
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			out[lastKey] += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		// First write wins — METADATA can repeat headers
		// (e.g. multiple Classifier entries) and we only care
		// about the singular Name/Version/...
		if _, exists := out[key]; !exists {
			out[key] = val
		}
		lastKey = key
	}
	return out
}

// purlPyPI renders a `pkg:pypi/<name>@<version>` PURL.
func purlPyPI(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return "pkg:pypi/" + name
	}
	return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
}

// dirOf returns p's directory part (everything before the last `/`),
// or "" when p has no `/`. Local helper that doesn't depend on
// path/filepath for a one-liner.
func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}
