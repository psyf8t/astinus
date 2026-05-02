// Package untracked discovers components that no upstream SBOM
// generator knew about — vendored binaries, downloaded archives,
// embedded JARs, statically linked Go binaries, scripts dropped in
// via curl|sh.
//
// Algorithm (per spec section 8.8):
//
//  1. Build the set of paths the input SBOM already mentions
//     (Component.Evidence.Locations across the whole tree).
//  2. Walk the image's filesystem in layered order (whiteout-aware,
//     via internal/image/layer.WalkFiles).
//  3. For each file NOT in the set:
//     - skip noise (pyc, locales, doc, …) — see classifier.go
//     - classify (executable / archive / library / script / config / …)
//     - hash + extract embedded metadata (Go buildinfo, JAR manifest)
//     - look the digest up via fingerprint/matcher
//  4. Append a Component to the SBOM with Evidence.Method
//     ("fingerprint" when the matcher answered, "untracked-scan"
//     otherwise).
//
// Limits:
//
//   - MaxComponents (default 10000) stops the scan once the SBOM
//     would otherwise blow up.
//   - MaxFileBytes (default 256 MiB) is the per-file cap on bytes
//     we hash / parse.
package untracked

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/psyf8t/astinus/internal/fingerprint"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable untracked`).
const Name = "untracked"

// Defaults — overridable via Options.
const (
	DefaultMaxComponents = 10000
	DefaultMaxFileBytes  = 256 << 20 // 256 MiB
	defaultMagicWindow   = 16
)

// Options controls the enricher.
type Options struct {
	// Matcher is queried for each hashed file. Nil → matcher.Null.
	Matcher matcher.Matcher
	// MaxComponents caps how many untracked components get added.
	// Zero → DefaultMaxComponents. Set to -1 to disable.
	MaxComponents int
	// MaxFileBytes caps how many bytes we hash per file.
	// Zero → DefaultMaxFileBytes.
	MaxFileBytes int64
}

// Enricher implements enrich.Enricher.
type Enricher struct {
	opts Options
}

// New returns a fresh Enricher with default options.
func New() *Enricher { return NewWithOptions(Options{}) }

// NewWithOptions returns an Enricher with custom options.
func NewWithOptions(o Options) *Enricher {
	if o.Matcher == nil {
		o.Matcher = matcher.Null
	}
	if o.MaxComponents == 0 {
		o.MaxComponents = DefaultMaxComponents
	}
	if o.MaxFileBytes == 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	return &Enricher{opts: o}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Enrich implements enrich.Enricher.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("untracked: missing sbom/bundle/image")
	}

	known := collectKnownPaths(sbom)
	added := 0

	visitor := func(ctx context.Context, fe layer.FileEntry, body io.Reader) error {
		if e.opts.MaxComponents > 0 && added >= e.opts.MaxComponents {
			return errLimitHit
		}
		if known[fe.Path] {
			return nil
		}
		comp, ok, err := e.processFile(ctx, fe, body)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		sbom.Components = append(sbom.Components, comp)
		added++
		return nil
	}

	err := layer.WalkFiles(ctx, bundle.Image, visitor)
	if errors.Is(err, errLimitHit) {
		return nil // hit the cap — accept what we collected
	}
	if err != nil {
		return fmt.Errorf("untracked: walk: %w", err)
	}
	return nil
}

// processFile runs one file through "slurp → classify → hash →
// extract → match" and returns the resulting Component (and ok=true)
// when the category warrants recording. ok=false for noise / config /
// static-archive (skipped); err is for true I/O errors.
func (e *Enricher) processFile(ctx context.Context, fe layer.FileEntry, body io.Reader) (model.Component, bool, error) {
	buf, err := readCapped(body, e.opts.MaxFileBytes)
	if err != nil {
		return model.Component{}, false, err
	}

	magic := buf
	if len(magic) > defaultMagicWindow {
		magic = magic[:defaultMagicWindow]
	}
	cls := Classify(fe.Path, magic)

	switch cls.Category {
	case CategoryNoise, CategoryStaticArchive, CategoryConfig:
		return model.Component{}, false, nil
	case CategoryExecutable, CategoryArchive, CategoryScript,
		CategoryLibrary, CategoryUnknown:
		// continue
	}

	hashes, _, hashErr := fingerprint.Hasher{}.Hash(bytes.NewReader(buf))
	if hashErr != nil {
		return model.Component{}, false, nil //nolint:nilerr // single-file hash failure must not abort the scan
	}
	sha256 := hashes[0].Value

	comp := buildBaseComponent(fe, cls, sha256, hashes)
	enrichEmbedded(&comp, cls.Category, buf)

	if m, lerr := e.opts.Matcher.Lookup(ctx, model.HashAlgorithmSHA256, sha256); lerr == nil {
		applyMatch(&comp, m)
		comp.Evidence.Method = "fingerprint"
	}
	return comp, true, nil
}

// enrichEmbedded looks for in-file metadata (Go buildinfo, JAR
// MANIFEST) and folds it onto comp.
func enrichEmbedded(comp *model.Component, cat Category, body []byte) {
	switch cat {
	case CategoryExecutable:
		if gobi, err := fingerprint.ReadGoBuildInfo(bytes.NewReader(body)); err == nil {
			attachGoBuildInfo(comp, gobi)
		}
	case CategoryArchive:
		if md, err := fingerprint.ReadJARMetadata(body); err == nil && md != nil {
			attachJARMetadata(comp, md)
		}
	case CategoryNoise, CategoryStaticArchive, CategoryScript,
		CategoryLibrary, CategoryConfig, CategoryUnknown:
		// no embedded-metadata extraction for these categories
	}
}

// errLimitHit is the internal sentinel that aborts WalkFiles when
// MaxComponents is reached.
var errLimitHit = errors.New("untracked: max components reached")

// collectKnownPaths gathers every Evidence.Locations path from sbom
// (recursing into SubComponents) into a set keyed on the path the
// untracked walker uses (no leading slash, normalised by callers
// when feeding evidence).
func collectKnownPaths(sbom *model.SBOM) map[string]bool {
	out := map[string]bool{}
	var visit func(comps []model.Component)
	visit = func(comps []model.Component) {
		for i := range comps {
			c := &comps[i]
			if c.Evidence != nil {
				for _, loc := range c.Evidence.Locations {
					out[normalize(loc.Path)] = true
				}
			}
			if len(c.SubComponents) > 0 {
				visit(c.SubComponents)
			}
		}
	}
	visit(sbom.Components)
	return out
}

func normalize(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

// buildBaseComponent fills in the fields every untracked Component
// gets regardless of category.
func buildBaseComponent(fe layer.FileEntry, cls Result, sha256Short string, hashes []model.Hash) model.Component {
	comp := model.Component{
		BOMRef: "untracked-" + sha256Short[:min(12, len(sha256Short))],
		Type:   componentTypeFor(cls.Category),
		Name:   path.Base(fe.Path),
		Hashes: hashes,
		Evidence: &model.Evidence{
			Method:    "untracked-scan",
			Locations: []model.EvidenceLocation{{Path: fe.Path}},
		},
		LayerInfo: &model.LayerInfo{
			LayerDigest: fe.Layer.Digest,
			LayerIndex:  fe.Layer.Index,
			AddedBy:     fe.Layer.CreatedBy,
		},
		Properties: map[string]string{
			"astinus:untracked:category": categoryString(cls.Category),
		},
	}
	return comp
}

// componentTypeFor maps a Category to the SBOM ComponentType it
// makes sense to record.
func componentTypeFor(c Category) model.ComponentType {
	switch c {
	case CategoryExecutable, CategoryScript:
		return model.ComponentTypeApplication
	case CategoryLibrary:
		return model.ComponentTypeLibrary
	case CategoryArchive:
		return model.ComponentTypeFile
	default:
		return model.ComponentTypeFile
	}
}

func categoryString(c Category) string {
	switch c {
	case CategoryExecutable:
		return "executable"
	case CategoryArchive:
		return "archive"
	case CategoryLibrary:
		return "library"
	case CategoryScript:
		return "script"
	case CategoryConfig:
		return "config"
	case CategoryStaticArchive:
		return "static-archive"
	case CategoryNoise:
		return "noise"
	default:
		return "unknown"
	}
}

// attachGoBuildInfo adds Go module info as SubComponents and wires
// the parent component's PURL when the main module is identifiable.
func attachGoBuildInfo(c *model.Component, bi *fingerprint.GoBuildInfo) {
	c.Properties["astinus:untracked:go-version"] = bi.GoVersion
	if bi.Main.Path != "" && bi.Main.Path != "command-line-arguments" {
		c.PURL = "pkg:golang/" + bi.Main.Path + "@" + nonEmpty(bi.Main.Version, "(devel)")
	}
	for _, dep := range bi.Deps {
		if dep.Path == "" {
			continue
		}
		c.SubComponents = append(c.SubComponents, model.Component{
			Type:    model.ComponentTypeLibrary,
			Name:    dep.Path,
			Version: dep.Version,
			PURL:    "pkg:golang/" + dep.Path + "@" + nonEmpty(dep.Version, ""),
		})
	}
}

// attachJARMetadata fills in name / version / vendor from the JAR
// manifest when those keys were populated.
func attachJARMetadata(c *model.Component, md *fingerprint.JARMetadata) {
	if md.BundleSymbolicName != "" {
		c.Name = md.BundleSymbolicName
	} else if md.ImplementationTitle != "" {
		c.Name = md.ImplementationTitle
	}
	if md.BundleVersion != "" {
		c.Version = md.BundleVersion
	} else if md.ImplementationVersion != "" {
		c.Version = md.ImplementationVersion
	}
	if md.ImplementationVendor != "" {
		c.Supplier = md.ImplementationVendor
	}
	c.Type = model.ComponentTypeLibrary
}

func applyMatch(c *model.Component, m matcher.Match) {
	if m.Name != "" {
		c.Name = m.Name
	}
	if m.Version != "" {
		c.Version = m.Version
	}
	if m.PURL != "" {
		c.PURL = m.PURL
	}
	if len(m.CPEs) > 0 {
		c.CPEs = append(c.CPEs, m.CPEs...)
	}
	if len(m.Licenses) > 0 {
		c.Licenses = append(c.Licenses, m.Licenses...)
	}
	if m.Source != "" {
		c.Properties["astinus:untracked:matcher"] = m.Source
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// readCapped reads up to limit+1 bytes; if the input is longer it
// returns an error (so the caller knows the file was over the cap).
// limit < 0 means unlimited.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return io.ReadAll(r)
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("untracked: file exceeds MaxFileBytes (%d)", limit)
	}
	return body, nil
}
