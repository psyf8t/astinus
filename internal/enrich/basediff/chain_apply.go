package basediff

import (
	"strconv"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// chainProperty names for layered-base visibility (S6 Task 4 /
// ADR-0061). All operator-readable, all under the existing
// `astinus:basediff:*` and `astinus:origin:*` namespaces so SBOM
// consumers reading the existing fields see the chain alongside.
const (
	propChainDepth       = "astinus:basediff:chain-depth"
	propChainLevelPrefix = "astinus:basediff:chain:"
	propOriginBaseLevel  = "astinus:origin:base-level"
	propOriginBaseRef    = "astinus:origin:base-ref"
)

// applyChain stamps SBOM-level + per-component chain metadata.
//
// Per-component: components currently classified as
// `OriginBaseImage` get `astinus:origin:base-level` and
// `astinus:origin:base-ref` indicating which level of the chain
// claims the component via its AddedPackages list. Components
// whose name matches no level keep their existing classification
// but receive no chain-level stamp.
//
// SBOM-level: `astinus:basediff:chain-depth` carries the number of
// resolved levels; `astinus:basediff:chain:<N>` enumerates each
// level's ImageRef (0-indexed; 0 is most-specific).
//
// Conservative override policy: we DO NOT flip `OriginApplication`
// → `OriginBaseImage` or vice versa even when the chain disagrees
// with the content strategy. The AddedPackages lists are a
// hand-curated minimal seed today (S6-T4 ships data + visibility;
// the curation toolchain is the Sprint 7 follow-up). A future
// task that ships complete AddedPackages data may add an
// authoritative override mode.
//
// ADR-0061.
func applyChain(sbom *model.SBOM, chain *BaseChain) {
	if sbom == nil || chain == nil {
		return
	}
	stampChainOnMetadata(sbom, chain)
	if chain.IsEmpty() {
		return
	}
	walkComponents(sbom.Components, func(c *model.Component) {
		if c.Origin != model.OriginBaseImage {
			return
		}
		level, ref, ok := chain.ClassifyByAddedPackages(c.Name)
		if !ok {
			return
		}
		if c.Properties == nil {
			c.Properties = map[string]string{}
		}
		c.Properties[propOriginBaseLevel] = strconv.Itoa(level)
		c.Properties[propOriginBaseRef] = ref
	})
}

// stampChainOnMetadata writes the SBOM-level chain stamps. Safe to
// call with an empty chain — stamps `chain-depth = 0` and clears
// any prior `chain:<N>` entries so re-enrich on a previously-
// enriched SBOM converges. S6 Task 4.
func stampChainOnMetadata(sbom *model.SBOM, chain *BaseChain) {
	if sbom == nil {
		return
	}
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	// Wipe prior chain entries so a shrinking chain on re-enrich
	// doesn't leave stale levels behind.
	for k := range sbom.Metadata.Properties {
		if startsWith(k, propChainLevelPrefix) {
			delete(sbom.Metadata.Properties, k)
		}
	}
	depth := 0
	if chain != nil {
		depth = len(chain.Levels)
	}
	sbom.Metadata.Properties[propChainDepth] = strconv.Itoa(depth)
	if chain == nil {
		return
	}
	for i, entry := range chain.Levels {
		if entry == nil {
			continue
		}
		sbom.Metadata.Properties[propChainLevelPrefix+strconv.Itoa(i)] = entry.ImageRef
	}
}

// startsWith is a tiny local helper — strings.HasPrefix in the
// stdlib would do the same thing, but inlined here avoids the
// import for one call site.
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
