package attribution

import (
	"strings"

	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// applyDebEarliest is the deb counterpart of applyApkEarliest
// (S6 Task 2 / ADR-0059). For every component whose PURL starts
// with `pkg:deb/`, looks up (Name, Version) in the FileMap's
// dpkg-earliest index and OVERRIDES LayerInfo + stamps
// `astinus:layer:source = "deb-earliest-layer"`.
//
// Why deb needs its own earliest path: `/var/lib/dpkg/status` is
// rewritten on every `apt-get install` / `apt-get remove` /
// `apt-get upgrade`. The FileMap's last-touch lookup against
// any of the deb-managed paths collapses pre-existing AND newly-
// added packages onto the last apt-touching layer. Sprint 7
// run-2's D-postgres benchmark measured 60 % origin accuracy with
// **bidirectional** mismatches — some debian:trixie-slim base
// packages labelled `application`, some postgres-added packages
// labelled `base`. The dpkg-earliest index restores per-package
// layer attribution analogous to apk-earliest.
//
// Runs AFTER the default stamper.applyAll AND after
// applyApkEarliest so non-deb components keep their attribution
// untouched. Idempotent — re-runs converge. S7 Task 3 / ADR-0060
// amendment.
func applyDebEarliest(comps []model.Component, fm *layer.FileMap) {
	if fm == nil {
		return
	}
	for i := range comps {
		c := &comps[i]
		if isDebComponent(c) {
			overrideToDebEarliest(c, fm)
		}
		if len(c.SubComponents) > 0 {
			applyDebEarliest(c.SubComponents, fm)
		}
	}
}

// overrideToDebEarliest looks the component's (name, version) up
// in the FileMap's dpkg-earliest index and, on a hit, overwrites
// LayerInfo + flips the `astinus:layer:source` stamp. On a miss
// the existing attribution (filemap-last-touch /
// syft-location-property / preexisting) is preserved. S7 Task 3.
func overrideToDebEarliest(c *model.Component, fm *layer.FileMap) {
	info, ok := fm.DpkgEarliestLayer(c.Name, c.Version)
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
	c.Properties[model.PropertyLayerSource] = "deb-earliest-layer"
}

// isDebComponent reports whether c is a deb-managed package — its
// PURL is `pkg:deb/<distro>/<name>@<version>` (Debian, Ubuntu).
// We match on the PURL prefix so SBOMs from Syft / Trivy / Astinus
// itself all flow through the same predicate. Components without
// a PURL never qualify.
func isDebComponent(c *model.Component) bool {
	if c == nil {
		return false
	}
	return strings.HasPrefix(c.PURL, "pkg:deb/")
}
