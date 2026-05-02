package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// FormatSummary is the CLI name for the human-readable summary
// renderer.
//
// The file is named `json_summary.go` per the spec section §15
// Stage 11 file list, but the body is not JSON — it's a plain-text
// report (spec §8.11 example). Naming kept for spec alignment.
const FormatSummary = "summary"

func init() {
	RegisterFormat(FormatSummary, func(_ Options) Renderer {
		return &summaryRenderer{}
	})
}

type summaryRenderer struct{}

func (s *summaryRenderer) Name() string     { return FormatSummary }
func (s *summaryRenderer) MIMEType() string { return "text/plain" }
func (s *summaryRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	if sbom == nil {
		return fmt.Errorf("summary: nil sbom")
	}

	stats := computeStats(sbom)
	var b strings.Builder
	writeHeader(&b, sbom)
	writeComponentSummary(&b, stats)
	writeUntrackedFindings(&b, stats)
	writeCPESummary(&b, stats)

	_, err := io.WriteString(w, b.String())
	return err
}

// imageRef formats a Component's `name[:version]` shorthand.
func imageRef(c *model.Component) string {
	if c == nil {
		return ""
	}
	if c.Version != "" {
		return c.Name + ":" + c.Version
	}
	return c.Name
}

// sha256Digest extracts the truncated SHA-256 from hashes (or "").
func sha256Digest(hashes []model.Hash) string {
	for _, h := range hashes {
		if h.Algorithm == model.HashAlgorithmSHA256 {
			return "sha256:" + truncate(h.Value, 12)
		}
	}
	return ""
}

// summaryStats aggregates everything the renderer wants to print.
type summaryStats struct {
	imageRef string
	digest   string

	totalComponents int
	fromBase        int
	application     int
	originUnknown   int

	untracked      []*model.Component
	untrackedAdded int

	componentsWithCPE int
	cpeAdded          int
	cpeAmbiguous      int
}

// tally adds c's contribution to the running stats.
func (s *summaryStats) tally(c *model.Component) {
	s.totalComponents++
	switch c.Origin {
	case model.OriginBaseImage:
		s.fromBase++
	case model.OriginApplication:
		s.application++
	case model.OriginUnknown:
		s.originUnknown++
	}
	if isUntracked(c) {
		s.untracked = append(s.untracked, c)
		s.untrackedAdded++
	}
	if len(c.CPEs) > 0 {
		s.componentsWithCPE++
	}
	if src := c.Properties["astinus:cpe:source"]; src != "" && src != "input" {
		s.cpeAdded++
	}
	if c.Properties["astinus:cpe:confidence"] == "low" {
		s.cpeAmbiguous++
	}
}

func computeStats(sbom *model.SBOM) summaryStats {
	s := summaryStats{}
	if sbom.Metadata.Component != nil {
		s.imageRef = imageRef(sbom.Metadata.Component)
		s.digest = sha256Digest(sbom.Metadata.Component.Hashes)
	}
	walkComponents(sbom.Components, func(c *model.Component) {
		s.tally(c)
	})
	sort.SliceStable(s.untracked, func(i, j int) bool {
		return untrackedSortKey(s.untracked[i]) < untrackedSortKey(s.untracked[j])
	})
	return s
}

func writeHeader(b *strings.Builder, sbom *model.SBOM) {
	if sbom.Metadata.Component != nil {
		fmt.Fprintf(b, "Image:  %s\n", componentLabel(sbom.Metadata.Component))
		for _, h := range sbom.Metadata.Component.Hashes {
			if h.Algorithm == model.HashAlgorithmSHA256 {
				fmt.Fprintf(b, "Digest: sha256:%s\n", h.Value)
				break
			}
		}
	} else {
		b.WriteString("Image:  (not declared in SBOM metadata)\n")
	}
	b.WriteByte('\n')
}

func writeComponentSummary(b *strings.Builder, s summaryStats) {
	b.WriteString("Component summary:\n")
	fmt.Fprintf(b, "  Total:           %d\n", s.totalComponents)
	if s.fromBase+s.application+s.originUnknown > 0 {
		fmt.Fprintf(b, "  From base:       %d\n", s.fromBase)
		fmt.Fprintf(b, "  Application:     %d\n", s.application)
		if s.originUnknown > 0 {
			fmt.Fprintf(b, "  Unknown origin:  %d\n", s.originUnknown)
		}
	}
	if s.untrackedAdded > 0 {
		fmt.Fprintf(b, "  Untracked added: %d\n", s.untrackedAdded)
	}
	b.WriteByte('\n')
}

func writeUntrackedFindings(b *strings.Builder, s summaryStats) {
	if len(s.untracked) == 0 {
		return
	}
	b.WriteString("Untracked findings:\n")
	for _, c := range s.untracked {
		marker := "?"
		if c.Evidence != nil && c.Evidence.Method == "fingerprint" {
			marker = "!"
		}
		path := ""
		if c.Evidence != nil && len(c.Evidence.Locations) > 0 {
			path = c.Evidence.Locations[0].Path
		}
		hash := ""
		for _, h := range c.Hashes {
			if h.Algorithm == model.HashAlgorithmSHA256 {
				hash = ", sha256:" + truncate(h.Value, 12)
				break
			}
		}
		switch {
		case path != "" && c.Version != "":
			fmt.Fprintf(b, "  %s %s (%s%s)\n", marker, path, c.Version, hash)
		case path != "":
			fmt.Fprintf(b, "  %s %s (%s%s)\n", marker, path, c.Name, hash)
		default:
			fmt.Fprintf(b, "  %s %s%s\n", marker, componentLabel(c), hash)
		}
	}
	b.WriteByte('\n')
}

func writeCPESummary(b *strings.Builder, s summaryStats) {
	if s.totalComponents == 0 {
		return
	}
	pct := 0.0
	if s.totalComponents > 0 {
		pct = float64(s.componentsWithCPE) * 100.0 / float64(s.totalComponents)
	}
	b.WriteString("CPE enrichment:\n")
	fmt.Fprintf(b, "  Components with CPE: %d/%d (%.1f%%)\n", s.componentsWithCPE, s.totalComponents, pct)
	if s.cpeAdded > 0 {
		fmt.Fprintf(b, "  Newly added:         %d\n", s.cpeAdded)
	}
	if s.cpeAmbiguous > 0 {
		fmt.Fprintf(b, "  Low-confidence:      %d (manual review recommended)\n", s.cpeAmbiguous)
	}
}

// untrackedSortKey orders untracked entries by evidence path (then
// name) for stable output.
func untrackedSortKey(c *model.Component) string {
	if c.Evidence != nil && len(c.Evidence.Locations) > 0 {
		return c.Evidence.Locations[0].Path
	}
	return c.Name
}

// truncate caps s at n runes (kept simple — every hex digest is ASCII).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
