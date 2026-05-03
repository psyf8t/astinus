package cluster

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// extractor is the per-anchor parser signature: given the anchor
// file's path and bytes, return the parsed Identity (or an error
// when the file is structurally invalid).
type extractor func(anchorPath string, content []byte) (Identity, error)

// anchorRule pairs a recogniser predicate with its extractor. Two
// shapes are supported:
//
//   - basename match (`Basename == file's path.Base(...)`). Covers
//     package.json, Cargo.toml, etc. — the dominant case.
//   - basename-with-suffix match (`SuffixOnBase`). Covers `*.gemspec`
//     and `dist-info/METADATA` (METADATA only counts when its parent
//     directory ends with `.dist-info`).
type anchorRule struct {
	Basename     string
	SuffixOnBase string // e.g., ".gemspec"; checked when Basename is empty
	Extract      extractor
}

// anchorRules is the in-priority-order list of anchors the detector
// recognises. Parser failures (bad JSON / XML / TOML) are silently
// dropped — a malformed manifest leaves the underlying directory to
// the density stage.
var anchorRules = []anchorRule{
	{Basename: "package.json", Extract: extractFromPackageJSON},
	{Basename: "Cargo.toml", Extract: extractFromCargoToml},
	{Basename: "go.mod", Extract: extractFromGoMod},
	{Basename: "pom.xml", Extract: extractFromPomXML},
	{Basename: "pyproject.toml", Extract: extractFromPyproject},
	{Basename: "METADATA", Extract: extractFromPythonMetadata},
	{Basename: "composer.json", Extract: extractFromComposerJSON},
	{Basename: "Chart.yaml", Extract: extractFromChartYaml},
	{SuffixOnBase: ".gemspec", Extract: extractFromGemspec},
}

// matchAnchor returns the extractor for filePath when the file is a
// recognised anchor. Returns nil when no rule matches.
func matchAnchor(filePath string) extractor {
	base := path.Base(filePath)
	for _, r := range anchorRules {
		if r.Basename != "" && base == r.Basename {
			if r.Basename == "METADATA" && !isPythonDistInfo(filePath) {
				continue
			}
			return r.Extract
		}
		if r.SuffixOnBase != "" && strings.HasSuffix(base, r.SuffixOnBase) {
			return r.Extract
		}
	}
	return nil
}

// isPythonDistInfo reports whether filePath is `<x>.dist-info/METADATA`.
// The METADATA basename also appears in unrelated contexts (Java
// META-INF directories, generic `metadata` files); only the
// `<package>-<version>.dist-info/METADATA` shape is a Python wheel.
func isPythonDistInfo(filePath string) bool {
	dir := path.Dir(filePath)
	return strings.HasSuffix(dir, ".dist-info")
}

// ─── Anchor extractors ──────────────────────────────────────────────

func extractFromPackageJSON(anchor string, body []byte) (Identity, error) {
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Identity{}, fmt.Errorf("package.json: %w", err)
	}
	if p.Name == "" {
		return Identity{}, fmt.Errorf("package.json: empty name")
	}
	return Identity{
		Name:            p.Name,
		Version:         p.Version,
		PURL:            purlNPM(p.Name, p.Version),
		Type:            "npm",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:package.json",
	}, nil
}

func extractFromCargoToml(anchor string, body []byte) (Identity, error) {
	name, version, ok := readTOMLPackageBlock(body)
	if !ok || name == "" {
		return Identity{}, fmt.Errorf("cargo.toml: no [package] block with name")
	}
	return Identity{
		Name:            name,
		Version:         version,
		PURL:            simplePURL("cargo", "", name, version),
		Type:            "cargo",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:Cargo.toml",
	}, nil
}

// goModuleLine matches a `module path/to/mod` directive. Captures the
// module path; the `module` keyword may be alone or followed by space.
var goModuleLine = regexp.MustCompile(`(?m)^module\s+(\S+)`)

func extractFromGoMod(anchor string, body []byte) (Identity, error) {
	m := goModuleLine.FindSubmatch(body)
	if m == nil {
		return Identity{}, fmt.Errorf("go.mod: no module directive")
	}
	modulePath := string(m[1])
	// go.mod doesn't carry a package version — version lives in the
	// VCS tag the operator attached. Cluster identity is still
	// useful with empty Version (PURL gets `@unknown` so consumers
	// can spot the gap).
	version := ""
	return Identity{
		Name:            modulePath,
		Version:         version,
		PURL:            purlGolang(modulePath, version),
		Type:            "golang",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:go.mod",
	}, nil
}

func extractFromPomXML(anchor string, body []byte) (Identity, error) {
	type ident struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	var pom struct {
		XMLName xml.Name `xml:"project"`
		ident
		Parent ident `xml:"parent"`
	}
	if err := xml.Unmarshal(body, &pom); err != nil {
		return Identity{}, fmt.Errorf("pom.xml: %w", err)
	}
	g := nonEmpty(pom.GroupID, pom.Parent.GroupID)
	a := nonEmpty(pom.ArtifactID, pom.Parent.ArtifactID)
	v := nonEmpty(pom.Version, pom.Parent.Version)
	if g == "" || a == "" {
		return Identity{}, fmt.Errorf("pom.xml: missing groupId/artifactId")
	}
	name := g + ":" + a
	return Identity{
		Name:            name,
		Version:         v,
		PURL:            purlMaven(g, a, v),
		Type:            "maven",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:pom.xml",
	}, nil
}

func extractFromPyproject(anchor string, body []byte) (Identity, error) {
	// PEP 621 puts metadata under [project]; older Poetry uses
	// [tool.poetry]. Try both.
	for _, section := range []string{"project", "tool.poetry"} {
		if name, version, ok := readTOMLNamedSection(body, section); ok && name != "" {
			return Identity{
				Name:            name,
				Version:         version,
				PURL:            simplePURL("pypi", "", name, version),
				Type:            "pypi",
				AnchorPath:      anchor,
				Confidence:      1.0,
				DetectionMethod: "anchor:pyproject.toml",
			}, nil
		}
	}
	return Identity{}, fmt.Errorf("pyproject.toml: no [project] or [tool.poetry] with name")
}

// extractFromPythonMetadata parses a `*.dist-info/METADATA` file
// (PEP 566 / RFC 822 format: header lines `Key: Value`). We only need
// `Name` and `Version`.
func extractFromPythonMetadata(anchor string, body []byte) (Identity, error) {
	var name, version string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // header section ended; description follows
		}
		switch {
		case strings.HasPrefix(line, "Name:"):
			name = strings.TrimSpace(line[len("Name:"):])
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(line[len("Version:"):])
		}
		if name != "" && version != "" {
			break
		}
	}
	if name == "" {
		return Identity{}, fmt.Errorf("METADATA: no Name header")
	}
	return Identity{
		Name:            name,
		Version:         version,
		PURL:            simplePURL("pypi", "", name, version),
		Type:            "pypi",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:dist-info/METADATA",
	}, nil
}

func extractFromComposerJSON(anchor string, body []byte) (Identity, error) {
	var c struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return Identity{}, fmt.Errorf("composer.json: %w", err)
	}
	if c.Name == "" {
		return Identity{}, fmt.Errorf("composer.json: empty name")
	}
	// Composer names are `vendor/package`; PURL splits accordingly.
	vendor, pkg, ok := strings.Cut(c.Name, "/")
	if !ok {
		return Identity{}, fmt.Errorf("composer.json: name %q is not vendor/package", c.Name)
	}
	return Identity{
		Name:            c.Name,
		Version:         c.Version,
		PURL:            simplePURL("composer", vendor, pkg, c.Version),
		Type:            "composer",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:composer.json",
	}, nil
}

func extractFromChartYaml(anchor string, body []byte) (Identity, error) {
	var c struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(body, &c); err != nil {
		return Identity{}, fmt.Errorf("chart.yaml: %w", err)
	}
	if c.Name == "" {
		return Identity{}, fmt.Errorf("chart.yaml: empty name")
	}
	return Identity{
		Name:            c.Name,
		Version:         c.Version,
		PURL:            simplePURL("helm", "", c.Name, c.Version),
		Type:            "helm",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:Chart.yaml",
	}, nil
}

// gemspecKey matches `s.name = "x"` / `spec.version = "y"` / variants
// with single quotes, with extra whitespace, and with `Gem::Version.new(...)`
// wrappers around the version.
var (
	gemspecName    = regexp.MustCompile(`(?m)^\s*\w+\.name\s*=\s*['"]([^'"]+)['"]`)
	gemspecVersion = regexp.MustCompile(`(?m)^\s*\w+\.version\s*=\s*(?:Gem::Version\.new\()?['"]([^'"]+)['"]`)
)

func extractFromGemspec(anchor string, body []byte) (Identity, error) {
	nm := gemspecName.FindSubmatch(body)
	if nm == nil {
		return Identity{}, fmt.Errorf("gemspec: no name assignment")
	}
	name := string(nm[1])
	var version string
	if vm := gemspecVersion.FindSubmatch(body); vm != nil {
		version = string(vm[1])
	}
	return Identity{
		Name:            name,
		Version:         version,
		PURL:            simplePURL("gem", "", name, version),
		Type:            "gem",
		AnchorPath:      anchor,
		Confidence:      1.0,
		DetectionMethod: "anchor:.gemspec",
	}, nil
}

// ─── PURL builders ──────────────────────────────────────────────────

func simplePURL(typ, namespace, name, version string) string {
	if name == "" {
		return ""
	}
	out := "pkg:" + typ + "/"
	if namespace != "" {
		out += namespace + "/"
	}
	out += name
	if version != "" {
		out += "@" + version
	}
	return out
}

func purlNPM(name, version string) string {
	// npm scoped package `@scope/name` → namespace = "@scope", name = "name".
	if strings.HasPrefix(name, "@") {
		if scope, base, ok := strings.Cut(name, "/"); ok {
			return simplePURL("npm", scope, base, version)
		}
	}
	return simplePURL("npm", "", name, version)
}

func purlGolang(modulePath, version string) string {
	v := version
	if v == "" {
		v = "unknown"
	}
	return "pkg:golang/" + modulePath + "@" + v
}

func purlMaven(group, artifact, version string) string {
	out := "pkg:maven/" + group + "/" + artifact
	if version != "" {
		out += "@" + version
	}
	return out
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ─── Targeted TOML parsing ──────────────────────────────────────────

// We parse only `[<section>] name = "..." version = "..."` blocks
// (`Cargo.toml`'s `[package]`, `pyproject.toml`'s `[project]` and
// `[tool.poetry]`). Hand-rolled to keep the package free of an
// external TOML dependency for two trivial keys.
//
// Limitations: nested tables under the section are walked through
// (we stop at the next `[...]` header). Strings must use `"..."` or
// `'...'`; multi-line strings, basic-string escapes, and array
// values are out of scope.

var (
	tomlSectionLine = regexp.MustCompile(`(?m)^\s*\[([^\]]+)\]\s*$`)
	tomlAssignLine  = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*['"]([^'"]+)['"]`)
)

// readTOMLPackageBlock returns the `name` + `version` keys from the
// `[package]` section, or ok=false when the section is absent.
func readTOMLPackageBlock(body []byte) (name, version string, ok bool) {
	return readTOMLNamedSection(body, "package")
}

// readTOMLNamedSection returns the `name` + `version` keys from the
// requested section (`section` is the literal text inside `[...]`,
// e.g. "package", "project", or "tool.poetry").
func readTOMLNamedSection(body []byte, section string) (name, version string, ok bool) {
	headerIdx := tomlSectionLine.FindAllSubmatchIndex(body, -1)
	for i, m := range headerIdx {
		header := strings.TrimSpace(string(body[m[2]:m[3]]))
		if header != section {
			continue
		}
		start := m[1]
		end := len(body)
		if i+1 < len(headerIdx) {
			end = headerIdx[i+1][0]
		}
		block := body[start:end]
		for _, am := range tomlAssignLine.FindAllSubmatch(block, -1) {
			key := string(am[1])
			val := string(am[2])
			switch key {
			case "name":
				name = val
			case "version":
				version = val
			}
			if name != "" && version != "" {
				return name, version, true
			}
		}
		return name, version, name != "" || version != ""
	}
	return "", "", false
}
