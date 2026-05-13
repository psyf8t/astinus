// Package cyclonedx converts between cdx.BOM (the cyclonedx-go wire
// type) and the canonical model.SBOM.
//
// Mapping policy
//
//   - Field-for-field where shapes match (BOMRef, Name, Version, PURL,
//     Hashes, Properties, …).
//   - OrganizationalEntity / OrganizationalContact are flattened to a
//     single Supplier / Author / Publisher string in MVP. The original
//     structure is preserved by the round-trip via SourceRaw fallback
//     in later stages; for now this is documented as a known-lossy area.
//   - CycloneDX exposes a single CPE per component; on read we put it
//     into Component.CPEs[0]. On write we emit CPEs[0] as the canonical
//     CPE and any extras as `astinus:cpe:N` properties so they survive
//     a CDX -> CDX round-trip even though CDX itself can't represent
//     them.
//   - LayerInfo / Origin (Astinus-added) are projected both into the
//     typed fields AND `astinus:*` Properties so CDX consumers without
//     the canonical model can still see them.
package cyclonedx

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// SpecVersionPrimary is the CycloneDX spec version this mapper writes
// when no other constraint is given. ADR-0002 makes the case for 1.6.
const SpecVersionPrimary = cdx.SpecVersion1_6

// componentTypeMap maps cdx.ComponentType values to the canonical
// model.ComponentType. Anything not listed becomes ComponentTypeUnknown.
var componentTypeMap = map[cdx.ComponentType]model.ComponentType{
	cdx.ComponentTypeApplication: model.ComponentTypeApplication,
	cdx.ComponentTypeContainer:   model.ComponentTypeContainer,
	cdx.ComponentTypeDevice:      model.ComponentTypeDevice,
	cdx.ComponentTypeFile:        model.ComponentTypeFile,
	cdx.ComponentTypeFirmware:    model.ComponentTypeFirmware,
	cdx.ComponentTypeFramework:   model.ComponentTypeFramework,
	cdx.ComponentTypeLibrary:     model.ComponentTypeLibrary,
	cdx.ComponentTypeOS:          model.ComponentTypeOS,
	cdx.ComponentTypePlatform:    model.ComponentTypePlatform,
}

// canonicalToCDX is the reverse mapping built lazily.
var canonicalToCDX = func() map[model.ComponentType]cdx.ComponentType {
	m := make(map[model.ComponentType]cdx.ComponentType, len(componentTypeMap))
	for k, v := range componentTypeMap {
		m[v] = k
	}
	return m
}()

// fromCDX converts an entire cdx.BOM into a canonical model.SBOM.
//
// raw is the original bytes; it's stashed on the SBOM so the writer can
// fall back to SourceRaw for unmapped fields in later stages.
func fromCDX(bom *cdx.BOM, raw []byte, sourceFormat model.Format) *model.SBOM {
	sbom := &model.SBOM{
		SourceFormat: sourceFormat,
		SourceRaw:    raw,
		Properties:   propsFromCDX(bom.Properties),
	}
	if bom.Metadata != nil {
		sbom.Metadata = metadataFromCDX(bom.Metadata)
	}
	if bom.Components != nil {
		sbom.Components = componentsFromCDX(*bom.Components)
	}
	if bom.Dependencies != nil {
		sbom.Relationships = relationshipsFromCDX(*bom.Dependencies)
	}
	return sbom
}

// toCDX converts a canonical model.SBOM back into a cdx.BOM ready for
// encoding at SpecVersionPrimary.
func toCDX(sbom *model.SBOM) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = SpecVersionPrimary
	if props := propsToCDX(sbom.Properties); len(props) > 0 {
		bom.Properties = &props
	}
	if md := metadataToCDX(sbom.Metadata); md != nil {
		bom.Metadata = md
	}
	if len(sbom.Components) > 0 {
		comps := componentsToCDX(sbom.Components)
		bom.Components = &comps
	}
	if len(sbom.Relationships) > 0 {
		deps := relationshipsToCDX(sbom.Relationships)
		bom.Dependencies = &deps
	}
	return bom
}

// ─── Metadata ──────────────────────────────────────────────────────────────

func metadataFromCDX(md *cdx.Metadata) model.Metadata {
	out := model.Metadata{
		Properties: propsFromCDX(md.Properties),
	}
	if md.Timestamp != "" {
		if t, err := parseTimestamp(md.Timestamp); err == nil {
			out.Timestamp = t
		}
	}
	if md.Authors != nil {
		for _, a := range *md.Authors {
			if name := strings.TrimSpace(a.Name); name != "" {
				out.Authors = append(out.Authors, name)
			}
		}
	}
	if md.Tools != nil {
		out.Tools = toolsFromCDX(md.Tools)
	}
	if md.Component != nil {
		c := componentFromCDX(*md.Component)
		out.Component = &c
	}
	return out
}

func metadataToCDX(md model.Metadata) *cdx.Metadata {
	out := &cdx.Metadata{}
	hasContent := false

	if !md.Timestamp.IsZero() {
		out.Timestamp = md.Timestamp.UTC().Format(timestampFormat)
		hasContent = true
	}
	if len(md.Authors) > 0 {
		authors := make([]cdx.OrganizationalContact, 0, len(md.Authors))
		for _, name := range md.Authors {
			authors = append(authors, cdx.OrganizationalContact{Name: name})
		}
		out.Authors = &authors
		hasContent = true
	}
	if len(md.Tools) > 0 {
		out.Tools = toolsToCDX(md.Tools)
		hasContent = true
	}
	if md.Component != nil {
		comp := componentToCDX(*md.Component)
		out.Component = &comp
		hasContent = true
	}
	if props := propsToCDX(md.Properties); len(props) > 0 {
		out.Properties = &props
		hasContent = true
	}

	if !hasContent {
		return nil
	}
	return out
}

func toolsFromCDX(tools *cdx.ToolsChoice) []model.Tool {
	if tools == nil {
		return nil
	}
	var out []model.Tool
	if tools.Components != nil {
		for _, c := range *tools.Components {
			vendor := ""
			if c.Supplier != nil {
				vendor = c.Supplier.Name
			} else if c.Group != "" {
				vendor = c.Group
			}
			out = append(out, model.Tool{
				Vendor:  vendor,
				Name:    c.Name,
				Version: c.Version,
			})
		}
	}
	if tools.Tools != nil {
		for _, t := range *tools.Tools {
			out = append(out, model.Tool{
				Vendor:  t.Vendor,
				Name:    t.Name,
				Version: t.Version,
			})
		}
	}
	return out
}

func toolsToCDX(tools []model.Tool) *cdx.ToolsChoice {
	comps := make([]cdx.Component, 0, len(tools))
	for _, t := range tools {
		c := cdx.Component{
			Type:    cdx.ComponentTypeApplication,
			Name:    t.Name,
			Version: t.Version,
		}
		if t.Vendor != "" {
			c.Supplier = &cdx.OrganizationalEntity{Name: t.Vendor}
		}
		comps = append(comps, c)
	}
	return &cdx.ToolsChoice{Components: &comps}
}

// ─── Components ────────────────────────────────────────────────────────────

func componentsFromCDX(in []cdx.Component) []model.Component {
	out := make([]model.Component, len(in))
	for i, c := range in {
		out[i] = componentFromCDX(c)
	}
	return out
}

func componentsToCDX(in []model.Component) []cdx.Component {
	out := make([]cdx.Component, len(in))
	for i, c := range in {
		out[i] = componentToCDX(c)
	}
	return out
}

func componentFromCDX(c cdx.Component) model.Component {
	out := model.Component{
		BOMRef:      c.BOMRef,
		Type:        mapComponentTypeFromCDX(c.Type),
		Group:       c.Group,
		Name:        c.Name,
		Version:     c.Version,
		Description: c.Description,
		Scope:       string(c.Scope),
		PURL:        c.PackageURL,
		Author:      c.Author,
		Publisher:   c.Publisher,
		Copyright:   c.Copyright,
		Properties:  propsFromCDX(c.Properties),
	}
	if c.Supplier != nil {
		out.Supplier = c.Supplier.Name
	}
	if c.CPE != "" {
		out.CPEs = append(out.CPEs, c.CPE)
	}
	if c.Hashes != nil {
		out.Hashes = hashesFromCDX(*c.Hashes)
	}
	if c.Licenses != nil {
		out.Licenses = licensesFromCDX(*c.Licenses)
	}
	if c.Evidence != nil {
		out.Evidence = evidenceFromCDX(c.Evidence)
	}
	if c.Components != nil {
		out.SubComponents = componentsFromCDX(*c.Components)
	}
	// Reconstruct LayerInfo / Origin / extra CPEs from properties so a
	// CDX file already enriched by Astinus round-trips losslessly.
	hydrateAstinusFields(&out)
	return out
}

func componentToCDX(c model.Component) cdx.Component {
	out := cdx.Component{
		BOMRef:      c.BOMRef,
		Type:        mapComponentTypeToCDX(c.Type),
		Group:       c.Group,
		Name:        c.Name,
		Version:     c.Version,
		Description: c.Description,
		Scope:       cdx.Scope(c.Scope),
		PackageURL:  c.PURL,
		Author:      c.Author,
		Publisher:   c.Publisher,
		Copyright:   c.Copyright,
	}
	if c.Supplier != "" {
		out.Supplier = &cdx.OrganizationalEntity{Name: c.Supplier}
	}
	if len(c.CPEs) > 0 {
		out.CPE = c.CPEs[0]
	}
	if hashes := hashesToCDX(c.Hashes); len(hashes) > 0 {
		out.Hashes = &hashes
	}
	if lics := licensesToCDX(c.Licenses); lics != nil {
		out.Licenses = lics
	}
	if c.Evidence != nil && !c.Evidence.IsZero() {
		out.Evidence = evidenceToCDX(c.Evidence)
	}
	if len(c.SubComponents) > 0 {
		subs := componentsToCDX(c.SubComponents)
		out.Components = &subs
	}

	// Properties = original + Astinus-added projection.
	props := mergeProperties(c.Properties, astinusProperties(&c))
	if len(props) > 0 {
		cdxProps := mapToCDXProperties(props)
		out.Properties = &cdxProps
	}

	return out
}

// hydrateAstinusFields reads `astinus:*` properties (which would be
// present when re-reading an SBOM that Astinus previously wrote) and
// populates the matching typed fields. It deletes the consumed
// properties so they don't get duplicated by the next write.
func hydrateAstinusFields(c *model.Component) {
	if len(c.Properties) == 0 {
		return
	}

	// Origin
	if v, ok := c.Properties[model.PropertyOrigin]; ok {
		c.Origin = model.Origin(v)
		delete(c.Properties, model.PropertyOrigin)
	}

	// LayerInfo
	li := model.LayerInfo{}
	hasLayer := false
	if v, ok := c.Properties[model.PropertyLayerDigest]; ok {
		li.LayerDigest = v
		delete(c.Properties, model.PropertyLayerDigest)
		hasLayer = true
	}
	if v, ok := c.Properties[model.PropertyLayerCompressedDigest]; ok {
		li.LayerCompressedDigest = v
		delete(c.Properties, model.PropertyLayerCompressedDigest)
		hasLayer = true
	}
	if v, ok := c.Properties[model.PropertyLayerIndex]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			li.LayerIndex = n
		}
		delete(c.Properties, model.PropertyLayerIndex)
		hasLayer = true
	}
	if v, ok := c.Properties[model.PropertyLayerDockerfileLine]; ok {
		li.DockerfileLine = v
		delete(c.Properties, model.PropertyLayerDockerfileLine)
		hasLayer = true
	}
	if v, ok := c.Properties[model.PropertyLayerAddedBy]; ok {
		li.AddedBy = v
		delete(c.Properties, model.PropertyLayerAddedBy)
		hasLayer = true
	}
	if hasLayer {
		c.LayerInfo = &li
	}

	// Extra CPEs serialized as astinus:cpe:1, astinus:cpe:2, ...
	for k := range c.Properties {
		if strings.HasPrefix(k, "astinus:cpe:") {
			c.CPEs = append(c.CPEs, c.Properties[k])
			delete(c.Properties, k)
		}
	}

	if len(c.Properties) == 0 {
		c.Properties = nil
	}
}

// astinusProperties returns the property-bag projection of the
// Astinus-typed fields on c.
func astinusProperties(c *model.Component) map[string]string {
	out := map[string]string{}
	if c.Origin != "" {
		out[model.PropertyOrigin] = string(c.Origin)
	}
	if c.LayerInfo != nil {
		li := c.LayerInfo
		if li.LayerDigest != "" {
			out[model.PropertyLayerDigest] = li.LayerDigest
		}
		if li.LayerCompressedDigest != "" {
			out[model.PropertyLayerCompressedDigest] = li.LayerCompressedDigest
		}
		out[model.PropertyLayerIndex] = strconv.Itoa(li.LayerIndex)
		if li.DockerfileLine != "" {
			out[model.PropertyLayerDockerfileLine] = li.DockerfileLine
		}
		if li.AddedBy != "" {
			out[model.PropertyLayerAddedBy] = li.AddedBy
		}
	}
	// Extra CPEs beyond the first land in numbered properties.
	for i, cpe := range c.CPEs {
		if i == 0 {
			continue
		}
		out[fmt.Sprintf("astinus:cpe:%d", i)] = cpe
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ─── Hash / License / Evidence ─────────────────────────────────────────────

func hashesFromCDX(in []cdx.Hash) []model.Hash {
	out := make([]model.Hash, len(in))
	for i, h := range in {
		out[i] = model.Hash{
			Algorithm: model.NormalizeHashAlgorithm(string(h.Algorithm)),
			Value:     h.Value,
		}
	}
	return out
}

func hashesToCDX(in []model.Hash) []cdx.Hash {
	if len(in) == 0 {
		return nil
	}
	out := make([]cdx.Hash, len(in))
	for i, h := range in {
		out[i] = cdx.Hash{
			Algorithm: cdx.HashAlgorithm(toCDXHashName(h.Algorithm)),
			Value:     h.Value,
		}
	}
	return out
}

// toCDXHashName converts the canonical lowercase algorithm name back to
// the CycloneDX spec spelling (e.g. "sha256" -> "SHA-256").
func toCDXHashName(s string) string {
	switch s {
	case model.HashAlgorithmMD5:
		return "MD5"
	case model.HashAlgorithmSHA1:
		return "SHA-1"
	case model.HashAlgorithmSHA256:
		return "SHA-256"
	case model.HashAlgorithmSHA384:
		return "SHA-384"
	case model.HashAlgorithmSHA512:
		return "SHA-512"
	case model.HashAlgorithmBlake2b256:
		return "BLAKE2b-256"
	case model.HashAlgorithmBlake2b512:
		return "BLAKE2b-512"
	case model.HashAlgorithmBlake3:
		return "BLAKE3"
	case model.HashAlgorithmSWHID:
		return "SWHID"
	default:
		// Pass through unchanged so unknown algos are preserved.
		return s
	}
}

func licensesFromCDX(in cdx.Licenses) []model.License {
	out := make([]model.License, 0, len(in))
	for _, lc := range in {
		switch {
		case lc.Expression != "":
			out = append(out, model.License{Expression: lc.Expression})
		case lc.License != nil:
			l := model.License{
				SPDXID: lc.License.ID,
				Name:   lc.License.Name,
				URL:    lc.License.URL,
			}
			if !l.IsEmpty() {
				out = append(out, l)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func licensesToCDX(in []model.License) *cdx.Licenses {
	if len(in) == 0 {
		return nil
	}
	out := make(cdx.Licenses, 0, len(in))
	for _, l := range in {
		if l.IsEmpty() {
			continue
		}
		switch {
		case l.IsExpression():
			out = append(out, cdx.LicenseChoice{Expression: l.Expression})
		default:
			out = append(out, cdx.LicenseChoice{License: &cdx.License{
				ID:   l.SPDXID,
				Name: l.Name,
				URL:  l.URL,
			}})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

func evidenceFromCDX(e *cdx.Evidence) *model.Evidence {
	if e == nil {
		return nil
	}
	out := model.Evidence{}
	if e.Identity != nil && len(*e.Identity) > 0 {
		// MVP: take the first identity entry's method name. The full
		// identity / technique / confidence triple is preserved by the
		// SourceRaw fallback in later stages.
		first := (*e.Identity)[0]
		out.Method = string(first.Field)
		out.Confidence = float32Ptr(first.Confidence)
	}
	if e.Occurrences != nil {
		for _, o := range *e.Occurrences {
			if o.Location != "" {
				out.Locations = append(out.Locations, model.EvidenceLocation{Path: o.Location})
			}
		}
	}
	if out.IsZero() {
		return nil
	}
	return &out
}

func evidenceToCDX(e *model.Evidence) *cdx.Evidence {
	if e == nil || e.IsZero() {
		return nil
	}
	out := &cdx.Evidence{}
	if e.Method != "" || e.Confidence != 0 {
		conf := float32(e.Confidence)
		identity := []cdx.EvidenceIdentity{{
			Field:      cdx.EvidenceIdentityFieldType(e.Method),
			Confidence: &conf,
		}}
		out.Identity = &identity
	}
	if len(e.Locations) > 0 {
		occs := make([]cdx.EvidenceOccurrence, 0, len(e.Locations))
		for _, loc := range e.Locations {
			occs = append(occs, cdx.EvidenceOccurrence{Location: loc.Path})
		}
		out.Occurrences = &occs
	}
	return out
}

// ─── Relationships / Dependencies ──────────────────────────────────────────

func relationshipsFromCDX(in []cdx.Dependency) []model.Relationship {
	var out []model.Relationship
	for _, d := range in {
		if d.Dependencies != nil {
			for _, dep := range *d.Dependencies {
				out = append(out, model.Relationship{
					SourceRef: d.Ref,
					TargetRef: dep,
					Type:      model.RelationshipDependsOn,
				})
			}
		}
		if d.Provides != nil {
			for _, prov := range *d.Provides {
				out = append(out, model.Relationship{
					SourceRef: d.Ref,
					TargetRef: prov,
					Type:      model.RelationshipProvides,
				})
			}
		}
	}
	return out
}

func relationshipsToCDX(in []model.Relationship) []cdx.Dependency {
	// Group by SourceRef so we emit one cdx.Dependency per source.
	bySource := map[string]*cdx.Dependency{}
	order := []string{}
	for _, r := range in {
		dep, ok := bySource[r.SourceRef]
		if !ok {
			dep = &cdx.Dependency{Ref: r.SourceRef}
			bySource[r.SourceRef] = dep
			order = append(order, r.SourceRef)
		}
		switch r.Type {
		case model.RelationshipDependsOn:
			if dep.Dependencies == nil {
				ds := []string{}
				dep.Dependencies = &ds
			}
			*dep.Dependencies = append(*dep.Dependencies, r.TargetRef)
		case model.RelationshipProvides:
			if dep.Provides == nil {
				ds := []string{}
				dep.Provides = &ds
			}
			*dep.Provides = append(*dep.Provides, r.TargetRef)
		case model.RelationshipContains, model.RelationshipUnknown:
			// CycloneDX expresses containment via nested components,
			// not dependencies — drop here. (Stage 1 fixtures don't
			// exercise this path.)
		}
	}
	out := make([]cdx.Dependency, 0, len(order))
	for _, ref := range order {
		out = append(out, *bySource[ref])
	}
	return out
}

// ─── Property bags ─────────────────────────────────────────────────────────

func propsFromCDX(in *[]cdx.Property) map[string]string {
	if in == nil || len(*in) == 0 {
		return nil
	}
	out := make(map[string]string, len(*in))
	for _, p := range *in {
		out[p.Name] = p.Value
	}
	return out
}

func propsToCDX(in map[string]string) []cdx.Property {
	if len(in) == 0 {
		return nil
	}
	return mapToCDXProperties(in)
}

func mapToCDXProperties(in map[string]string) []cdx.Property {
	out := make([]cdx.Property, 0, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable / deterministic output
	for _, k := range keys {
		out = append(out, cdx.Property{Name: k, Value: in[k]})
	}
	return out
}

func mergeProperties(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func mapComponentTypeFromCDX(t cdx.ComponentType) model.ComponentType {
	if v, ok := componentTypeMap[t]; ok {
		return v
	}
	return model.ComponentTypeUnknown
}

func mapComponentTypeToCDX(t model.ComponentType) cdx.ComponentType {
	if v, ok := canonicalToCDX[t]; ok {
		return v
	}
	// Fallback: write whatever string we have. CDX accepts custom
	// types in practice even if the schema is strict.
	return cdx.ComponentType(string(t))
}

func float32Ptr(p *float32) float64 {
	if p == nil {
		return 0
	}
	return float64(*p)
}
