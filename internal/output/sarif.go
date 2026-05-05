package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/version"
)

// FormatSARIF is the CLI name for the SARIF 2.1.0 renderer.
const FormatSARIF = "sarif"

func init() {
	RegisterFormat(FormatSARIF, func(o Options) Renderer {
		return &sarifRenderer{pretty: o.Pretty}
	})
}

// sarifRenderer projects the canonical SBOM into SARIF 2.1.0 results.
//
// What counts as a "finding" (per ADR-0013):
//
//   - **warning** — untracked components (Evidence.Method ==
//     "untracked-scan"): something we discovered the upstream SBOM
//     missed.
//   - **note** — components stamped Origin == OriginUnknown: a
//     diff-status concern, less severe than untracked.
//   - **note** — components carrying a PURL but no CPEs after Stage 6
//     ran (cpe enricher's lookup couldn't resolve them).
//   - **note** — components whose CPE was added with low confidence
//     (Properties["astinus:cpe:confidence"] == "low").
//
// SARIF result locations point at:
//
//   - the file path from Component.Evidence.Locations[0] when present,
//   - otherwise the BOMRef as a logical location.
type sarifRenderer struct{ pretty bool }

func (s *sarifRenderer) Name() string     { return FormatSARIF }
func (s *sarifRenderer) MIMEType() string { return "application/sarif+json" }
func (s *sarifRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	if sbom == nil {
		return fmt.Errorf("sarif: nil sbom")
	}

	doc := buildSARIFDocument(sbom)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if s.pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}
	return nil
}

// ─── SARIF 2.1.0 minimal struct subset ────────────────────────────────────

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// ─── Builder ──────────────────────────────────────────────────────────────

// Rule IDs emitted by Astinus. Stable across versions; downstream
// tooling matches by these strings.
const (
	ruleUntracked        = "ASTINUS001"
	ruleOriginUnknown    = "ASTINUS002"
	ruleMissingCPE       = "ASTINUS003"
	ruleLowConfidenceCPE = "ASTINUS004"
)

func buildSARIFDocument(sbom *model.SBOM) sarifDocument {
	rules := []sarifRule{
		{
			ID:               ruleUntracked,
			Name:             "UntrackedComponent",
			ShortDescription: sarifMessage{Text: "Component discovered by Astinus that the input SBOM did not list."},
			Properties:       map[string]any{"category": "untracked-scan"},
		},
		{
			ID:               ruleOriginUnknown,
			Name:             "OriginUnknown",
			ShortDescription: sarifMessage{Text: "Component cannot be classified as base or application layer."},
			Properties:       map[string]any{"category": "basediff"},
		},
		{
			ID:               ruleMissingCPE,
			Name:             "MissingCPE",
			ShortDescription: sarifMessage{Text: "Component has a PURL but no CPE — vulnerability scanners will likely miss it."},
			Properties:       map[string]any{"category": "cpe"},
		},
		{
			ID:               ruleLowConfidenceCPE,
			Name:             "LowConfidenceCPE",
			ShortDescription: sarifMessage{Text: "CPE was inferred heuristically; manual review recommended."},
			Properties:       map[string]any{"category": "cpe"},
		},
	}

	results := collectResults(sbom.Components)
	// Deterministic order so tests and `git diff` between runs stay stable.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].Message.Text < results[j].Message.Text
	})

	return sarifDocument{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "astinus",
				Version:        version.Version,
				InformationURI: "https://github.com/psyf8t/astinus",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// collectResults walks every component (recursing into SubComponents)
// and emits one or more SARIF results per component as appropriate.
func collectResults(comps []model.Component) []sarifResult {
	var out []sarifResult
	walkComponents(comps, func(c *model.Component) {
		out = append(out, resultsForComponent(c)...)
	})
	return out
}

// resultsForComponent returns the SARIF results that apply to c.
// A single component can produce multiple results (e.g. untracked +
// missing CPE); each rule fires independently.
func resultsForComponent(c *model.Component) []sarifResult {
	var out []sarifResult
	if isUntracked(c) {
		out = append(out, sarifResult{
			RuleID:    ruleUntracked,
			Level:     "warning",
			Message:   sarifMessage{Text: untrackedMessage(c)},
			Locations: locationsFor(c),
		})
	}
	if c.Origin == model.OriginUnknown {
		out = append(out, sarifResult{
			RuleID:    ruleOriginUnknown,
			Level:     "note",
			Message:   sarifMessage{Text: fmt.Sprintf("Component %q has Origin=unknown.", componentLabel(c))},
			Locations: locationsFor(c),
		})
	}
	if c.PURL != "" && len(c.CPEs) == 0 {
		out = append(out, sarifResult{
			RuleID:    ruleMissingCPE,
			Level:     "note",
			Message:   sarifMessage{Text: fmt.Sprintf("Component %q (PURL %q) has no CPE.", componentLabel(c), c.PURL)},
			Locations: locationsFor(c),
		})
	}
	if c.Properties != nil && isLowConfidenceCPE(c.Properties["astinus:cpe:confidence"]) {
		out = append(out, sarifResult{
			RuleID:    ruleLowConfidenceCPE,
			Level:     "note",
			Message:   sarifMessage{Text: fmt.Sprintf("Component %q has a low-confidence CPE (heuristic).", componentLabel(c))},
			Locations: locationsFor(c),
		})
	}
	return out
}

// isUntracked reports whether c was added by the Stage-4 untracked
// enricher.
func isUntracked(c *model.Component) bool {
	if c.Evidence != nil && c.Evidence.Method == "untracked-scan" {
		return true
	}
	if c.Properties != nil {
		if cat, ok := c.Properties["astinus:untracked:category"]; ok && cat != "" {
			return true
		}
	}
	return false
}

// untrackedMessage builds a human-readable description for the
// untracked rule: "Untracked <category> 'name' found at /path".
func untrackedMessage(c *model.Component) string {
	cat := "component"
	if c.Properties != nil {
		if v := c.Properties["astinus:untracked:category"]; v != "" {
			cat = v
		}
	}
	loc := ""
	if c.Evidence != nil && len(c.Evidence.Locations) > 0 {
		loc = c.Evidence.Locations[0].Path
	}
	if loc != "" {
		return fmt.Sprintf("Untracked %s %q found at %s.", cat, componentLabel(c), loc)
	}
	return fmt.Sprintf("Untracked %s %q.", cat, componentLabel(c))
}

// componentLabel picks the most useful display name for c.
func componentLabel(c *model.Component) string {
	switch {
	case c.Name != "" && c.Version != "":
		return c.Name + "@" + c.Version
	case c.Name != "":
		return c.Name
	case c.PURL != "":
		return c.PURL
	default:
		return c.BOMRef
	}
}

// locationsFor builds SARIF locations from a component's evidence.
func locationsFor(c *model.Component) []sarifLocation {
	if c.Evidence != nil && len(c.Evidence.Locations) > 0 {
		out := make([]sarifLocation, 0, len(c.Evidence.Locations))
		for _, l := range c.Evidence.Locations {
			out = append(out, sarifLocation{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: cleanURI(l.Path)},
				},
			})
		}
		return out
	}
	if c.BOMRef != "" {
		return []sarifLocation{{
			LogicalLocations: []sarifLogicalLocation{{Name: c.BOMRef, Kind: "package"}},
		}}
	}
	return nil
}

// cleanURI strips the leading slash so SARIF artifactLocation reads
// as a workspace-relative path (GitHub Code Scanning expects that).
func cleanURI(p string) string {
	return strings.TrimPrefix(p, "/")
}

// isLowConfidenceCPE reports whether the `astinus:cpe:confidence`
// stamp signals a low-confidence (heuristic) primary CPE. Sprint 3
// Task 0 changed the stamp from a coarse string label ("low" / "high")
// to a numeric "0.50" / "0.95"; the helper accepts either form so
// previously-enriched SBOMs still light up the SARIF rule.
func isLowConfidenceCPE(stamp string) bool {
	if stamp == "" {
		return false
	}
	if stamp == "low" {
		return true
	}
	v, err := parseConfidence(stamp)
	if err != nil {
		return false
	}
	// Match Threshold.AlternativeMin: anything strictly above the
	// alternative floor reads as "good enough" — i.e. the rule fires
	// on candidates that just squeak through.
	return v < 0.70
}

// parseConfidence reads the "%.2f" format the cpe enricher writes.
// Returns (value, nil) on success, (0, err) on a parse failure so
// callers can decide whether to fall back to the legacy label.
func parseConfidence(s string) (float64, error) {
	var v float64
	if _, err := fmt.Sscanf(s, "%f", &v); err != nil {
		return 0, err
	}
	return v, nil
}

// walkComponents recurses depth-first into SubComponents.
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}
