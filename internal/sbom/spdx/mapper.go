// Package spdx converts between the SPDX 2.3 wire format and the
// canonical SBOM model.
//
// SPDX 2.3 is the primary version; SPDX 3.0 has a substantially
// different shape and is deferred to a future stage. CycloneDX
// remains the project's first-class wire format — SPDX support is
// here so Astinus can consume Syft's `-o spdx-json` output and
// produce SPDX for downstream consumers that prefer it.
//
// Mapping policy
//
//   - Document level: SPDX `Document` <-> canonical `model.SBOM`.
//   - Component level: SPDX `Package` <-> canonical `Component`.
//     Packages are flat in SPDX, so canonical `SubComponents` are
//     emitted as additional Packages plus a `CONTAINS` relationship
//     from the parent. On read, `CONTAINS` relationships pointing
//     to known packages re-establish nesting.
//   - PURL is emitted as `externalRefs[referenceType=purl]`.
//   - Each CPE is emitted as `externalRefs[referenceType=cpe23Type]`.
//   - Hashes <-> SPDX checksums (algorithm names normalised).
//   - Astinus typed fields (LayerInfo / Origin / Properties) are
//     serialised as SPDX Annotations with Comment of the form
//     `<key>=<value>` where the key uses the same `astinus:*`
//     namespace as the CycloneDX writer.
package spdx

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/version"
)

// SpecVersionPrimary is the SPDX version this package writes by
// default ("SPDX-2.3").
const SpecVersionPrimary = "SPDX-2.3"

// rfc3339UTC is the timestamp shape SPDX requires for annotations.
const rfc3339UTC = "2006-01-02T15:04:05Z"

// fromSPDX converts an SPDX 2.3 Document into the canonical model.
//
// raw is the original bytes; it's stashed on the SBOM so writers can
// fall back to SourceRaw for unmapped fields in later stages.
func fromSPDX(doc *v23.Document, raw []byte, sourceFormat model.Format) *model.SBOM {
	sbom := &model.SBOM{
		SourceFormat: sourceFormat,
		SourceRaw:    raw,
		Properties:   propsFromAnnotations(derefAnnotations(doc.Annotations)),
	}
	sbom.Metadata = metadataFromDoc(doc)
	sbom.Components = componentsFromPackages(doc.Packages)
	hydrateRelationships(sbom, doc.Relationships)
	return sbom
}

// toSPDX converts the canonical model into an SPDX 2.3 Document
// ready for encoding.
func toSPDX(sbom *model.SBOM) *v23.Document {
	doc := &v23.Document{
		SPDXVersion:       SpecVersionPrimary,
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    common.ElementID("DOCUMENT"),
		DocumentName:      docName(sbom),
		DocumentNamespace: docNamespace(sbom),
		CreationInfo:      creationInfo(),
	}

	if anns := annotationsFromProps(propsToOrderedSlice(sbom.Properties)); len(anns) > 0 {
		doc.Annotations = pointerAnnotations(anns)
	}

	docRef := common.DocElementID{ElementRefID: doc.SPDXIdentifier}

	// Emit packages depth-first; nested SubComponents become extra
	// packages + CONTAINS relationships.
	var (
		packages []*v23.Package
		rels     []*v23.Relationship
	)
	for i := range sbom.Components {
		emitComponent(&sbom.Components[i], &packages, &rels)
	}
	doc.Packages = packages

	// Top-level DESCRIBES relationship for every package directly
	// owned by the document.
	for _, c := range sbom.Components {
		rels = append(rels, &v23.Relationship{
			RefA:         docRef,
			RefB:         common.DocElementID{ElementRefID: pkgID(&c)},
			Relationship: "DESCRIBES",
		})
	}

	// Convert canonical Relationships.
	for _, r := range sbom.Relationships {
		spdxRelType := canonicalToSPDXRelType(r.Type)
		if spdxRelType == "" {
			continue
		}
		rels = append(rels, &v23.Relationship{
			RefA:         common.DocElementID{ElementRefID: common.ElementID(refToID(r.SourceRef))},
			RefB:         common.DocElementID{ElementRefID: common.ElementID(refToID(r.TargetRef))},
			Relationship: spdxRelType,
		})
	}
	doc.Relationships = rels

	return doc
}

// ─── Document-level helpers ───────────────────────────────────────────────

func docName(sbom *model.SBOM) string {
	if sbom.Metadata.Component != nil && sbom.Metadata.Component.Name != "" {
		return sbom.Metadata.Component.Name
	}
	return "astinus-sbom"
}

// docNamespace synthesises a per-document namespace. Real producers
// use a fully-qualified URI; we use the project URL plus a stable
// suffix derived from the primary component name.
func docNamespace(sbom *model.SBOM) string {
	suffix := docName(sbom)
	return "https://github.com/psyf8t/astinus/sbom/" + suffix
}

func creationInfo() *v23.CreationInfo {
	return &v23.CreationInfo{
		Created: time.Now().UTC().Format(rfc3339UTC),
		Creators: []common.Creator{
			{CreatorType: "Tool", Creator: "astinus-" + version.Version},
		},
		LicenseListVersion: "3.23",
	}
}

func metadataFromDoc(doc *v23.Document) model.Metadata {
	out := model.Metadata{Properties: propsFromAnnotations(derefAnnotations(doc.Annotations))}
	if doc.CreationInfo == nil {
		return out
	}
	if doc.CreationInfo.Created != "" {
		if t, err := time.Parse(rfc3339UTC, doc.CreationInfo.Created); err == nil {
			out.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, doc.CreationInfo.Created); err == nil {
			out.Timestamp = t.UTC()
		}
	}
	for _, c := range doc.CreationInfo.Creators {
		switch c.CreatorType {
		case "Tool":
			vendor, name, ver := splitTool(c.Creator)
			out.Tools = append(out.Tools, model.Tool{Vendor: vendor, Name: name, Version: ver})
		case "Person", "Organization":
			out.Authors = append(out.Authors, c.Creator)
		}
	}
	return out
}

// splitTool extracts (vendor, name, version) from an SPDX
// `creator: "Tool: <vendor> <name>-<version>"` style string. SPDX
// gives us a single string, so we do best-effort parsing.
func splitTool(s string) (vendor, name, ver string) {
	if i := strings.LastIndex(s, "-"); i > 0 {
		ver = s[i+1:]
		s = s[:i]
	}
	if i := strings.LastIndex(s, " "); i > 0 {
		name = s[i+1:]
		vendor = s[:i]
	} else {
		name = s
	}
	return vendor, name, ver
}

// ─── Component <-> Package ────────────────────────────────────────────────

// emitComponent appends c (and its nested SubComponents) as packages
// + CONTAINS relationships into the slices the caller is building.
func emitComponent(c *model.Component, packages *[]*v23.Package, rels *[]*v23.Relationship) {
	pkg := componentToPackage(c)
	*packages = append(*packages, pkg)
	for i := range c.SubComponents {
		child := &c.SubComponents[i]
		emitComponent(child, packages, rels)
		*rels = append(*rels, &v23.Relationship{
			RefA:         common.DocElementID{ElementRefID: pkg.PackageSPDXIdentifier},
			RefB:         common.DocElementID{ElementRefID: pkgID(child)},
			Relationship: "CONTAINS",
		})
	}
}

func componentToPackage(c *model.Component) *v23.Package {
	pkg := &v23.Package{
		PackageName:             c.Name,
		PackageSPDXIdentifier:   pkgID(c),
		PackageVersion:          c.Version,
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
	}
	if c.Supplier != "" {
		pkg.PackageSupplier = &common.Supplier{SupplierType: "Organization", Supplier: c.Supplier}
	}
	if c.Copyright != "" {
		pkg.PackageCopyrightText = c.Copyright
	}
	if c.Description != "" {
		pkg.PackageDescription = c.Description
	}
	if len(c.Hashes) > 0 {
		pkg.PackageChecksums = checksumsFromHashes(c.Hashes)
	}
	if l := licenseExpression(c.Licenses); l != "" {
		pkg.PackageLicenseConcluded = l
		pkg.PackageLicenseDeclared = l
	}
	if refs := externalRefs(c); len(refs) > 0 {
		pkg.PackageExternalReferences = refs
	}
	if anns := annotationsForComponent(c); len(anns) > 0 {
		pkg.Annotations = anns
	}
	return pkg
}

// pkgID derives the SPDXRef for a Component. Falls back to a
// synthetic id when BOMRef is empty so every package has a unique
// identifier.
func pkgID(c *model.Component) common.ElementID {
	if c.BOMRef != "" {
		return common.ElementID(refToID(c.BOMRef))
	}
	// last-ditch: name+version, sanitised.
	return common.ElementID(refToID(c.Name + "-" + c.Version))
}

// refToID coerces an arbitrary string into a valid SPDX idstring
// (alphanumeric + ".-").
func refToID(s string) string {
	if s == "" {
		return "Package"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func componentsFromPackages(pkgs []*v23.Package) []model.Component {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]model.Component, 0, len(pkgs))
	for _, p := range pkgs {
		// tools-golang's JSON loader can hand us a nil entry on
		// malformed input (FuzzReadJSON corpus 76ba3524…). Skip
		// rather than panic; a missing component is preferable to
		// a hard crash on hostile or buggy SBOMs.
		if p == nil {
			continue
		}
		out = append(out, packageToComponent(p))
	}
	return out
}

func packageToComponent(p *v23.Package) model.Component {
	c := model.Component{
		BOMRef:      string(p.PackageSPDXIdentifier),
		Type:        model.ComponentTypeLibrary,
		Name:        p.PackageName,
		Version:     p.PackageVersion,
		Description: p.PackageDescription,
		Copyright:   p.PackageCopyrightText,
		Properties:  propsFromAnnotations(p.Annotations),
	}
	if p.PackageSupplier != nil {
		c.Supplier = p.PackageSupplier.Supplier
	}
	if p.PackageLicenseConcluded != "" && p.PackageLicenseConcluded != "NOASSERTION" {
		c.Licenses = []model.License{{Expression: p.PackageLicenseConcluded}}
	} else if p.PackageLicenseDeclared != "" && p.PackageLicenseDeclared != "NOASSERTION" {
		c.Licenses = []model.License{{Expression: p.PackageLicenseDeclared}}
	}
	c.Hashes = hashesFromChecksums(p.PackageChecksums)
	for _, ref := range p.PackageExternalReferences {
		switch ref.RefType {
		case "purl":
			c.PURL = ref.Locator
		case "cpe23Type":
			c.CPEs = append(c.CPEs, ref.Locator)
		}
	}
	hydrateAstinusFields(&c)
	return c
}

// ─── Relationships ────────────────────────────────────────────────────────

func hydrateRelationships(sbom *model.SBOM, rels []*v23.Relationship) {
	if len(rels) == 0 {
		return
	}
	// Build lookup from SPDXRef -> *Component for nesting.
	byID := map[string]*model.Component{}
	for i := range sbom.Components {
		byID[sbom.Components[i].BOMRef] = &sbom.Components[i]
	}
	var keep []model.Relationship
	consumed := map[string]bool{}
	for _, r := range rels {
		if r == nil {
			continue
		}
		from := string(r.RefA.ElementRefID)
		to := string(r.RefB.ElementRefID)
		switch r.Relationship {
		case "DESCRIBES":
			// Document-level edge — drop on read; the writer adds
			// it back deterministically.
		case "CONTAINS":
			parent, parentOK := byID[from]
			child, childOK := byID[to]
			if parentOK && childOK {
				parent.SubComponents = append(parent.SubComponents, *child)
				consumed[to] = true
				continue
			}
			keep = append(keep, model.Relationship{
				SourceRef: from, TargetRef: to, Type: model.RelationshipContains,
			})
		default:
			keep = append(keep, model.Relationship{
				SourceRef: from, TargetRef: to,
				Type: spdxRelTypeToCanonical(r.Relationship),
			})
		}
	}
	if len(consumed) > 0 {
		filtered := sbom.Components[:0]
		for _, c := range sbom.Components {
			if !consumed[c.BOMRef] {
				filtered = append(filtered, c)
			}
		}
		sbom.Components = filtered
	}
	sbom.Relationships = keep
}

func canonicalToSPDXRelType(t model.RelationshipType) string {
	switch t {
	case model.RelationshipDependsOn:
		return "DEPENDS_ON"
	case model.RelationshipProvides:
		return "DEPENDENCY_OF" // best mirror in SPDX
	case model.RelationshipContains:
		return "CONTAINS"
	default:
		return ""
	}
}

func spdxRelTypeToCanonical(s string) model.RelationshipType {
	switch s {
	case "DEPENDS_ON":
		return model.RelationshipDependsOn
	case "DEPENDENCY_OF":
		return model.RelationshipProvides
	case "CONTAINS":
		return model.RelationshipContains
	default:
		return model.RelationshipUnknown
	}
}

// ─── Hashes / Licenses / External Refs ────────────────────────────────────

func checksumsFromHashes(in []model.Hash) []common.Checksum {
	out := make([]common.Checksum, 0, len(in))
	for _, h := range in {
		alg := spdxChecksumAlgo(h.Algorithm)
		if alg == "" {
			continue
		}
		out = append(out, common.Checksum{Algorithm: alg, Value: h.Value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hashesFromChecksums(in []common.Checksum) []model.Hash {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.Hash, 0, len(in))
	for _, c := range in {
		out = append(out, model.Hash{
			Algorithm: model.NormalizeHashAlgorithm(string(c.Algorithm)),
			Value:     c.Value,
		})
	}
	return out
}

// spdxChecksumAlgo maps the canonical (lowercase, normalised) algorithm
// name to the SPDX-spec spelling.
func spdxChecksumAlgo(s string) common.ChecksumAlgorithm {
	switch s {
	case model.HashAlgorithmMD5:
		return common.MD5
	case model.HashAlgorithmSHA1:
		return common.SHA1
	case model.HashAlgorithmSHA256:
		return common.SHA256
	case model.HashAlgorithmSHA384:
		return common.SHA384
	case model.HashAlgorithmSHA512:
		return common.SHA512
	default:
		return ""
	}
}

// licenseExpression collapses the canonical License slice into a
// single SPDX expression. Multiple structured entries get joined
// with " AND ". Empty / NOASSERTION entries are skipped.
func licenseExpression(in []model.License) string {
	parts := make([]string, 0, len(in))
	for _, l := range in {
		switch {
		case l.Expression != "":
			parts = append(parts, l.Expression)
		case l.SPDXID != "":
			parts = append(parts, l.SPDXID)
		case l.Name != "":
			parts = append(parts, l.Name)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts, " AND ")
}

func externalRefs(c *model.Component) []*v23.PackageExternalReference {
	var refs []*v23.PackageExternalReference
	if c.PURL != "" {
		refs = append(refs, &v23.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  c.PURL,
		})
	}
	for _, cpe := range c.CPEs {
		refs = append(refs, &v23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "cpe23Type",
			Locator:  cpe,
		})
	}
	return refs
}

// ─── Annotations <-> Properties / Astinus typed fields ────────────────────

// annotator is the canonical creator string Astinus stamps onto every
// annotation it produces.
func annotator() common.Annotator {
	return common.Annotator{AnnotatorType: "Tool", Annotator: "astinus-" + version.Version}
}

// annotationsForComponent serialises Astinus typed fields PLUS
// arbitrary Properties into SPDX Annotations.
func annotationsForComponent(c *model.Component) []v23.Annotation {
	props := mergeProps(c.Properties, astinusComponentProps(c))
	return annotationsFromProps(propsToOrderedSlice(props))
}

// astinusComponentProps projects the typed fields (LayerInfo, Origin,
// CPE overflow) into the property bag keys Stage 1 already declared.
func astinusComponentProps(c *model.Component) map[string]string {
	out := map[string]string{}
	if c.Origin != "" {
		out[model.PropertyOrigin] = string(c.Origin)
	}
	if c.LayerInfo != nil {
		li := c.LayerInfo
		if li.LayerDigest != "" {
			out[model.PropertyLayerDigest] = li.LayerDigest
		}
		out[model.PropertyLayerIndex] = strconv.Itoa(li.LayerIndex)
		if li.DockerfileLine != "" {
			out[model.PropertyLayerDockerfileLine] = li.DockerfileLine
		}
		if li.AddedBy != "" {
			out[model.PropertyLayerAddedBy] = li.AddedBy
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// hydrateAstinusFields scans the component's properties for
// `astinus:layer:*` / `astinus:origin` keys and projects them back
// onto the typed fields. Keys consumed are deleted from the property
// map so a second writer doesn't double-emit them.
func hydrateAstinusFields(c *model.Component) {
	if len(c.Properties) == 0 {
		return
	}
	if v, ok := c.Properties[model.PropertyOrigin]; ok {
		c.Origin = model.Origin(v)
		delete(c.Properties, model.PropertyOrigin)
	}
	li := model.LayerInfo{}
	hasLayer := false
	if v, ok := c.Properties[model.PropertyLayerDigest]; ok {
		li.LayerDigest = v
		delete(c.Properties, model.PropertyLayerDigest)
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
	if len(c.Properties) == 0 {
		c.Properties = nil
	}
}

// annotationsFromProps emits one annotation per (key, value) pair.
func annotationsFromProps(in []propPair) []v23.Annotation {
	if len(in) == 0 {
		return nil
	}
	out := make([]v23.Annotation, 0, len(in))
	now := time.Now().UTC().Format(rfc3339UTC)
	for _, p := range in {
		out = append(out, v23.Annotation{
			Annotator:         annotator(),
			AnnotationDate:    now,
			AnnotationType:    "OTHER",
			AnnotationComment: p.key + "=" + p.value,
		})
	}
	return out
}

// propsFromAnnotations parses Annotations whose comment is
// `<key>=<value>` shape back into a property map. Annotations that
// don't fit the pattern are ignored.
func propsFromAnnotations(in []v23.Annotation) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, a := range in {
		comment := a.AnnotationComment
		idx := strings.Index(comment, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(comment[:idx])
		val := comment[idx+1:]
		if key == "" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ─── Property-bag helpers ─────────────────────────────────────────────────

type propPair struct{ key, value string }

func mergeProps(base, extra map[string]string) map[string]string {
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

// propsToOrderedSlice turns a map into a sorted (by key) slice so
// the annotation order is deterministic.
func propsToOrderedSlice(in map[string]string) []propPair {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]propPair, 0, len(keys))
	for _, k := range keys {
		out = append(out, propPair{key: k, value: in[k]})
	}
	return out
}

// Tiny sort to avoid pulling sort just for one call. Insertion sort is
// fine for the small property bags we see in practice (single digits).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		x := s[i]
		j := i
		for j > 0 && s[j-1] > x {
			s[j] = s[j-1]
			j--
		}
		s[j] = x
	}
}

var _ = fmt.Errorf // reserved for future error wrapping

// pointerAnnotations converts a value slice to a pointer slice (for
// Document.Annotations which uses []*Annotation).
func pointerAnnotations(in []v23.Annotation) []*v23.Annotation {
	if len(in) == 0 {
		return nil
	}
	out := make([]*v23.Annotation, len(in))
	for i := range in {
		anno := in[i]
		out[i] = &anno
	}
	return out
}

// derefAnnotations is the inverse of pointerAnnotations.
func derefAnnotations(in []*v23.Annotation) []v23.Annotation {
	if len(in) == 0 {
		return nil
	}
	out := make([]v23.Annotation, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		out = append(out, *p)
	}
	return out
}
