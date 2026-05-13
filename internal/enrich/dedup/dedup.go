// Package dedup is the SBOM finalize stage that merges duplicate
// components emitted by upstream tools or by Astinus's own untracked
// scan.
//
// The dedup enricher is intentionally the LAST in the pipeline so it
// sees the SBOM after every other enricher has had a chance to add
// PURLs, CPEs, and properties. Duplicates that share a stronger
// identifier (PURL > CPE > SHA-256 > name+version+type) get merged
// into a single component with the union of evidence, properties,
// hashes, licenses, and CPEs.
//
// Components without ANY identifying signal stay separate — two
// `name="config.txt", type="file"` components without versions are
// not assumed to be the same file.
//
// post-Stage-13 hardening sprint Task 2.
package dedup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable dedup`).
const Name = "dedup"

// Enricher merges duplicate components in the SBOM. Implements
// enrich.Enricher so the pipeline can run it just like any other
// enricher; semantically it is a finalize stage and should always
// be last.
type Enricher struct{}

// New returns a fresh Enricher.
func New() *Enricher { return &Enricher{} }

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. PRSD-Task-6: dedup is
// the finalize stage — it MUST run AFTER basediff (which sets
// Origin) and AFTER cpe (which adds CPEs that participate in the
// dedup key). S3 Task 1 adds "extractor" so the lifted
// embedded-dependency components also feed the dedup key. S3
// Task 4 adds "registry" so registry-derived hashes / supplier /
// licenses participate too. `TopoSort` places dedup last regardless
// of input order.
func (*Enricher) Dependencies() []string {
	return []string{"basediff", "cpe", "extractor", "registry"}
}

// Enrich implements enrich.Enricher. The bundle is unused; dedup
// works purely on the in-memory SBOM.
func (e *Enricher) Enrich(_ context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("dedup: nil sbom")
	}
	before := len(sbom.Components)
	sbom.Components, _ = Run(sbom.Components)
	after := len(sbom.Components)

	slog.Default().Info("dedup.complete",
		"before", before,
		"after", after,
		"removed", before-after,
	)
	return nil
}

// Run merges duplicates in comps and returns (deduplicated slice,
// number of merged groups). Exported so callers (tests, CLI flags,
// future finalize stage refactor) can drive it without going
// through the enricher machinery.
func Run(comps []model.Component) ([]model.Component, int) {
	if len(comps) == 0 {
		return comps, 0
	}

	// S5 Task 3: when a Go-module coordinate (same module path)
	// shows up with both an Astinus buildinfo row and a Syft-or-
	// other-inherited row, drop the inherited one BEFORE the
	// purl-keyed merge. The buildinfo row's version reflects the
	// actually-compiled module — Syft's `go-mod-cataloger` parses
	// go.mod / go.sum which can drift (replace directives, vendor
	// selection, build-cache reuse). Run #3 measured 16 of 19
	// golang FPs originating from this divergence; ADR-0050.
	comps = preferBuildinfoForGoModules(comps)

	// Two passes:
	//   1. Bucket components by dedup key. Components with no key
	//      (key=="") are appended to a "no-key" pile and pass through.
	//   2. Merge each bucket of >1 into one component; bucket of 1
	//      passes through unchanged.
	type bucket struct {
		first int
		idxs  []int
	}
	buckets := map[string]*bucket{}

	for i := range comps {
		k := dedupKey(&comps[i])
		if k == "" {
			// No identifying signal — passes through at original
			// position in the second walk; no bucketing needed.
			continue
		}
		b, ok := buckets[k]
		if !ok {
			buckets[k] = &bucket{first: i, idxs: []int{i}}
			continue
		}
		b.idxs = append(b.idxs, i)
	}

	out := make([]model.Component, 0, len(comps))
	mergedGroups := 0

	// Preserve original order: walk comps once, emit a component the
	// first time we see its bucket (merged), skip subsequent
	// occurrences. Components in noKey emit at their original index.
	emitted := make(map[string]bool, len(buckets))
	for i := range comps {
		k := dedupKey(&comps[i])
		if k == "" {
			out = append(out, comps[i])
			continue
		}
		b := buckets[k]
		if emitted[k] {
			continue
		}
		emitted[k] = true
		if len(b.idxs) == 1 {
			out = append(out, comps[i])
			continue
		}
		// Multi-element bucket: choose primary, merge the rest.
		primary := pickPrimary(comps, b.idxs)
		merged := comps[primary]
		for _, idx := range b.idxs {
			if idx == primary {
				continue
			}
			merged = mergePair(merged, comps[idx])
		}
		out = append(out, merged)
		mergedGroups++
	}
	return out, mergedGroups
}

// dedupKey returns a canonical identity for a component. Components
// with the same key are merged. Returns "" when the component has no
// identifying signal — those pass through without dedup.
//
// Priority (most-precise wins):
//
//  1. PURL                — strongest cross-tool identifier
//  2. CPE                 — second-strongest
//  3. SHA-256             — content identity for binaries without metadata
//  4. type+name+version   — last-resort name match
//  5. (none)              — return "" → pass through
func dedupKey(c *model.Component) string {
	if c.PURL != "" {
		return "purl:" + canonicalPURL(c.PURL)
	}
	if cpe := firstNonEmpty(c.CPEs); cpe != "" {
		return "cpe:" + canonicalCPE(cpe)
	}
	if h := findHash(c, model.HashAlgorithmSHA256); h != "" {
		return "sha256:" + strings.ToLower(h)
	}
	if c.Name != "" && c.Version != "" {
		return fmt.Sprintf("nvt:%s:%s:%s",
			strings.ToLower(string(c.Type)),
			strings.ToLower(c.Name),
			strings.ToLower(c.Version))
	}
	return ""
}

// canonicalPURL trims a `?qualifier=...` suffix if present so two
// components with the same package/version but different qualifiers
// (e.g. Syft adds `?package-id=...`) match. The base PURL is the
// dedup identity.
func canonicalPURL(p string) string {
	if idx := strings.IndexByte(p, '?'); idx > 0 {
		return strings.ToLower(p[:idx])
	}
	return strings.ToLower(p)
}

// canonicalCPE lowercases the CPE so Syft's mixed-case quirks
// (`cpe:2.3:a:DABH:\@colors\/colors:...` vs
// `cpe:2.3:a:\@colors\/colors:...`) don't defeat dedup.
func canonicalCPE(cpe string) string { return strings.ToLower(strings.TrimSpace(cpe)) }

// findHash returns the value of the first hash matching algorithm
// (case-insensitive). Returns "" when not present.
func findHash(c *model.Component, algorithm string) string {
	want := strings.ToLower(algorithm)
	for _, h := range c.Hashes {
		if strings.ToLower(h.Algorithm) == want && h.Value != "" {
			return h.Value
		}
	}
	return ""
}

// firstNonEmpty returns the first non-empty string in s.
func firstNonEmpty(s []string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// pickPrimary chooses which index in idxs is the "primary" component
// — the one that survives the merge as the base. Tiebreaker order:
//
//  1. Component with a PURL beats one without.
//  2. Component with more Evidence.Locations wins (more provenance).
//  3. Original-order earliest index (stable choice).
func pickPrimary(comps []model.Component, idxs []int) int {
	best := idxs[0]
	bestScore := primaryScore(&comps[best])
	for _, i := range idxs[1:] {
		s := primaryScore(&comps[i])
		switch {
		case s > bestScore:
			best, bestScore = i, s
		case s == bestScore && i < best:
			best = i
		}
	}
	return best
}

// primaryScore is a small integer that captures "how strong is this
// component as a primary candidate." Higher beats lower. The exact
// values don't matter; only the ordering does.
//
// S4 Task 1 adds the `evidence-level = identified` bump so a
// buildinfo-grounded Go module wins primary against a parallel
// `type = file` Syft row pointing at the same package coordinates.
// Without this, the file row's missing PURL still produces a tie at
// the PURL band when both have one, and the wrong row could be
// picked as primary by original-index tiebreak.
func primaryScore(c *model.Component) int {
	score := 0
	if c.PURL != "" {
		score += 100
	}
	if len(c.CPEs) > 0 {
		score += 10
	}
	if c.Evidence != nil {
		score += len(c.Evidence.Locations)
	}
	if c.Properties[model.PropertyEvidenceLevel] == string(model.EvidenceLevelIdentified) {
		score += 50
	}
	// A `file` typed row is the weakest signal of identity; prefer
	// any row that has been classified more precisely.
	if c.Type != "" && c.Type != model.ComponentTypeFile {
		score += 5
	}
	return score
}

// mergePair returns a component that carries the union of primary +
// secondary's evidence, properties, hashes, licenses, and CPEs.
// On conflicts the primary's value wins (with secondary surfaced as
// a property breadcrumb when interesting).
//
// S4 Task 1: when the primary's Type is the weak `file` and the
// secondary carries a more-precise Type (library / application),
// the merge upgrades. This keeps a Syft `file`-typed apk row from
// silently masking a go-buildinfo `library`-typed row that happens
// to share the same PURL.
func mergePair(primary, secondary model.Component) model.Component {
	out := primary

	if out.Type == model.ComponentTypeFile && secondary.Type != "" &&
		secondary.Type != model.ComponentTypeFile {
		out.Type = secondary.Type
	}

	// Locations: union (dedup by path).
	out.Evidence = mergeEvidence(primary.Evidence, secondary.Evidence)

	// Hashes: union by (algorithm, value).
	out.Hashes = mergeHashes(primary.Hashes, secondary.Hashes)

	// CPEs: union (preserve order, drop case-insensitive duplicates).
	out.CPEs = mergeCPEs(primary.CPEs, secondary.CPEs)

	// Licenses: union (dedup by Expression OR (SPDX, Name)).
	out.Licenses = mergeLicenses(primary.Licenses, secondary.Licenses)

	// Properties: union with primary winning on conflict; record the
	// secondary value under a breadcrumb so it isn't lost silently.
	out.Properties = mergeProperties(primary.Properties, secondary.Properties)

	// LayerInfo: keep primary's. If they differ, record secondary's
	// layer index for the consumer.
	if primary.LayerInfo != nil && secondary.LayerInfo != nil &&
		primary.LayerInfo.LayerIndex != secondary.LayerInfo.LayerIndex {
		if out.Properties == nil {
			out.Properties = map[string]string{}
		}
		out.Properties["astinus:dedup:also-in-layer"] = fmt.Sprintf("%d",
			secondary.LayerInfo.LayerIndex)
	} else if primary.LayerInfo == nil && secondary.LayerInfo != nil {
		out.LayerInfo = secondary.LayerInfo
	}

	// Stamp how many components were folded so consumers see dedup
	// happened (and how aggressively).
	if out.Properties == nil {
		out.Properties = map[string]string{}
	}
	prev := 0
	if v, ok := out.Properties["astinus:dedup:merged-count"]; ok {
		_, _ = fmt.Sscanf(v, "%d", &prev)
	}
	out.Properties["astinus:dedup:merged-count"] = fmt.Sprintf("%d", prev+1)

	return out
}

func mergeEvidence(a, b *model.Evidence) *model.Evidence {
	if a == nil && b == nil {
		return nil
	}
	out := &model.Evidence{}
	if a != nil {
		*out = *a
	}
	if b != nil {
		if out.Method == "" {
			out.Method = b.Method
		}
		if out.Confidence == 0 {
			out.Confidence = b.Confidence
		}
	}
	seen := map[string]bool{}
	for _, loc := range out.Locations {
		seen[loc.Path] = true
	}
	if b != nil {
		for _, loc := range b.Locations {
			if !seen[loc.Path] {
				out.Locations = append(out.Locations, loc)
				seen[loc.Path] = true
			}
		}
	}
	return out
}

func mergeHashes(a, b []model.Hash) []model.Hash {
	seen := map[string]bool{}
	out := make([]model.Hash, 0, len(a)+len(b))
	for _, h := range append(append([]model.Hash{}, a...), b...) {
		if h.Value == "" {
			continue
		}
		k := strings.ToLower(h.Algorithm) + ":" + strings.ToLower(h.Value)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	return out
}

func mergeCPEs(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, cpe := range append(append([]string{}, a...), b...) {
		k := canonicalCPE(cpe)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, cpe)
	}
	return out
}

func mergeLicenses(a, b []model.License) []model.License {
	seen := map[string]bool{}
	out := make([]model.License, 0, len(a)+len(b))
	for _, lic := range append(append([]model.License{}, a...), b...) {
		k := strings.ToLower(strings.TrimSpace(lic.Expression))
		if k == "" {
			k = strings.ToLower(strings.TrimSpace(lic.SPDXID)) + "|" +
				strings.ToLower(strings.TrimSpace(lic.Name))
		}
		if k == "|" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, lic)
	}
	return out
}

func mergeProperties(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if existing, ok := out[k]; ok && existing != v {
			// Conflict — preserve secondary value under a breadcrumb.
			out["astinus:dedup:conflict:"+k] = v
			continue
		}
		out[k] = v
	}
	return out
}

// preferBuildinfoForGoModules drops Syft-inherited (or
// otherwise-sourced) `pkg:golang/<path>@<version>` rows when an
// Astinus buildinfo-derived row exists for the SAME module path
// at a DIFFERENT version. Run #3 benchmark on the Grafana digest
// measured 16 of 19 golang FPs originating from this divergence:
// Syft's `go-mod-cataloger` parses go.mod / go.sum (intended
// dependencies) which can drift from the compiled version due to
// replace directives, vendor selection, or build-cache reuse.
// The buildinfo row reads `debug/buildinfo` from the actually-
// compiled binary and is authoritative.
//
// SAME-version overlap (Syft + buildinfo both report the exact
// canonical PURL) passes through to the normal PURL-keyed merge
// downstream — that's the S4-T1 contract where syft:location:*
// breadcrumbs from the Syft row survive the merge while the
// buildinfo row's evidence-level=identified wins primary. ADR-0050.
//
// Components that aren't `pkg:golang/` PURLs pass through
// untouched.
func preferBuildinfoForGoModules(comps []model.Component) []model.Component {
	if len(comps) == 0 {
		return comps
	}
	// First pass: collect the canonical PURLs of buildinfo rows
	// (already include `@version`) AND the set of module paths
	// they cover. We drop only non-buildinfo rows whose module
	// path is in the path set BUT whose canonical PURL isn't in
	// the exact set — i.e. different-version shadow.
	buildinfoExactPURLs := make(map[string]bool)
	buildinfoModulePaths := make(map[string]bool)
	for i := range comps {
		c := &comps[i]
		if !isGolangPURL(c.PURL) {
			continue
		}
		if c.Properties["astinus:identified:source"] != "go-buildinfo" {
			continue
		}
		buildinfoExactPURLs[canonicalPURL(c.PURL)] = true
		buildinfoModulePaths[goModulePathFromPURL(c.PURL)] = true
	}
	if len(buildinfoModulePaths) == 0 {
		return comps
	}
	// Second pass: keep buildinfo rows + non-golang rows + golang
	// rows whose canonical PURL exactly matches a buildinfo row
	// (same version → normal merge handles it). Drop golang rows
	// at the same module path with a different version when a
	// buildinfo row exists.
	out := make([]model.Component, 0, len(comps))
	for i := range comps {
		c := comps[i]
		if !isGolangPURL(c.PURL) {
			out = append(out, c)
			continue
		}
		if c.Properties["astinus:identified:source"] == "go-buildinfo" {
			out = append(out, c)
			continue
		}
		// Non-buildinfo golang row. Check the two cases.
		if buildinfoExactPURLs[canonicalPURL(c.PURL)] {
			// Same module path AND same version as a buildinfo
			// row — let the normal PURL-keyed merge handle it
			// (S4-T1 contract: syft:location:* breadcrumb
			// survives, evidence-level=identified wins primary).
			out = append(out, c)
			continue
		}
		if buildinfoModulePaths[goModulePathFromPURL(c.PURL)] {
			// Different version at the same module path — drop
			// the non-buildinfo row. The buildinfo version is
			// authoritative.
			continue
		}
		// No buildinfo row at this module path. Pass through —
		// the inherited entry stays as-is.
		out = append(out, c)
	}
	return out
}

// isGolangPURL reports whether purl is shaped `pkg:golang/...`.
func isGolangPURL(purl string) bool {
	return strings.HasPrefix(purl, "pkg:golang/")
}

// goModulePathFromPURL returns the module-path coordinate from a
// golang PURL with version + qualifiers stripped. Empty string for
// inputs that aren't golang PURLs.
func goModulePathFromPURL(purl string) string {
	if !isGolangPURL(purl) {
		return ""
	}
	base := purl
	if i := strings.IndexByte(base, '@'); i > 0 {
		base = base[:i]
	}
	if j := strings.IndexByte(base, '?'); j > 0 {
		base = base[:j]
	}
	if k := strings.IndexByte(base, '#'); k > 0 {
		base = base[:k]
	}
	return base
}
