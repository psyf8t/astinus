package attribution

import (
	"strings"

	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// applyApkEarliest overrides LayerInfo for every apk component
// (`pkg:apk/...` PURL) with the EARLIEST layer in which the apk DB
// (`/lib/apk/db/installed`) listed (name, version). The default
// last-touch / Syft-location stamps point at the layer that last
// rewrote the apk DB — typically the last layer with `apk add` —
// which is wrong for `astinus:origin` classification:
//
//	A base alpine image typically ships an apk DB listing every
//	package (musl, busybox, …). Later layers that run `apk add curl`
//	rewrite the DB to include curl + carry forward the originals.
//	The FileMap's last-touch lookup against any of the apk-managed
//	paths collapses both pre-existing AND newly-added packages onto
//	the same (last) layer index, and basediff then classifies all
//	of them as `base-image` even when the operator added them in
//	the application layer.
//
// The apk-earliest index distinguishes the two cases by tracking
// the layer in which a (name, version) tuple FIRST appeared in the
// DB. Components that appear in layer 0 (the base) stay base;
// components added later carry their actual introduction layer.
//
// The override is applied AFTER the regular last-touch / Syft
// stamping (so non-apk components are unaffected and the apk
// override has a known starting state to replace). The stamp's
// `astinus:layer:source = "apk-earliest-layer"` records the
// provenance so audit downstreams can tell apart the two paths.
// S6 Task 2 / ADR-0059.
func applyApkEarliest(comps []model.Component, fm *layer.FileMap) {
	if fm == nil {
		return
	}
	for i := range comps {
		c := &comps[i]
		if isApkComponent(c) {
			overrideToApkEarliest(c, fm)
		}
		if len(c.SubComponents) > 0 {
			applyApkEarliest(c.SubComponents, fm)
		}
	}
}

// overrideToApkEarliest looks the component's (name, version) up in
// the FileMap's apk-earliest index and, on a hit, overwrites
// LayerInfo + flips the `astinus:layer:source` stamp. On a miss the
// existing attribution (filemap-last-touch / syft-location-property
// / preexisting) is preserved. Exported for the unit tests; not
// part of the package's external API.
func overrideToApkEarliest(c *model.Component, fm *layer.FileMap) {
	info, ok := fm.ApkEarliestLayer(c.Name, c.Version)
	if !ok {
		return
	}
	c.LayerInfo = &model.LayerInfo{
		LayerDigest:           info.DiffID,
		LayerCompressedDigest: info.CompressedDigest,
		LayerIndex:            info.Index,
		AddedBy:               info.CreatedBy,
	}
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	// Source stamp is REPLACED (not preserved) so re-runs don't
	// carry stale syft-location-property breadcrumbs for apk rows.
	c.Properties[model.PropertyLayerSource] = "apk-earliest-layer"
}

// isApkComponent reports whether c is an apk-managed package — its
// PURL is `pkg:apk/<distro>/<name>@<version>` (Alpine, Wolfi, etc).
// We match on the PURL prefix so SBOMs from Syft / Trivy / Astinus
// itself all flow through the same predicate. Components without a
// PURL never qualify; the apk-earliest override is a per-package
// concept, not a per-file one.
func isApkComponent(c *model.Component) bool {
	if c == nil {
		return false
	}
	return strings.HasPrefix(c.PURL, "pkg:apk/")
}
