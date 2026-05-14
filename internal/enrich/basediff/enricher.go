package basediff

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/psyf8t/astinus/internal/enrich/basediff/contenthash"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/image/source"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable basediff`).
const Name = "basediff"

// Options configures the enricher.
type Options struct {
	// Mode controls base-image resolution. Zero value = ModeAuto.
	Mode Mode

	// Reference is the base image ref used in ModeExplicit. Ignored
	// for the other modes.
	Reference string

	// SourceOpts are forwarded to image.Open when pulling the base
	// image. Use this to plumb the same transport / credentials /
	// platform the CLI configured for the target.
	SourceOpts []source.Option

	// DisableContentBaseDetection turns off the S4 Task 6
	// content-based detection fallback (os-release + bundled
	// known-bases catalogue) when label-based detection returns
	// empty under ModeAuto. Default false → detection runs.
	DisableContentBaseDetection bool

	// BaseMinConfidence is the threshold AutoDetector applies when
	// picking the highest-scoring catalogue entry. Zero value
	// triggers the helper's own default (0.70). S4 Task 6.
	BaseMinConfidence float64
}

// Enricher implements enrich.Enricher.
type Enricher struct {
	opts     Options
	detector *AutoDetector
}

// New returns an Enricher with default options (Mode=Auto).
func New() *Enricher { return NewWithOptions(Options{}) }

// NewWithOptions returns an Enricher with the supplied options. The
// content-based detector is wired in unless the bundled known-bases
// snapshot fails to load (treated as a soft fallback — label-based
// detection still works without it). S4 Task 6.
func NewWithOptions(o Options) *Enricher {
	e := &Enricher{opts: o}
	if !o.DisableContentBaseDetection {
		if known, err := LoadBundledKnownBases(); err == nil {
			e.detector = NewAutoDetector(known, o.BaseMinConfidence)
		}
	}
	return e
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. PRSD-Task-6: basediff
// MUST run AFTER untracked so the content-addressable strategy
// can classify untracked-added components, not just the Syft set.
// The Hardening-Sprint-1 order ran basediff first; the topo sort
// reorders so the new dep is honoured.
func (*Enricher) Dependencies() []string { return []string{"untracked"} }

// Enrich implements enrich.Enricher.
//
// Always returns nil — basediff is best-effort. Failures (no
// detected base, base unreachable, etc.) downgrade to "everyone is
// unknown" or, when target labels carry a base.digest, the partial
// mode heuristic.
//
// Strategy (PRSD-Task-2): when the base image loads successfully,
// run the content-addressable diff first — hash every visible file
// in both images, classify SBOM components by SHA-256 match. This
// works on multi-stage / squashed / distroless builds where the
// legacy layer-prefix and path-fallback diffs misclassify.
//
// If the content scan fails (e.g. the base image has too many
// files to hash within memory limits, or a layer is unreadable),
// fall back to layer.ComputeDiff (prefix → path-fallback) to
// preserve the Hardening-Sprint-1 behaviour.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("basediff: missing sbom/bundle/image")
	}

	logger := slog.Default()

	if e.opts.Mode == ModeNone {
		return nil
	}

	baseRef, err := e.resolveBaseRef(ctx, sbom, bundle)
	if err != nil || baseRef == "" {
		e.handleNoBase(logger, sbom, baseRef, err)
		stampStrategy(sbom, "unavailable")
		return nil
	}

	baseBundle, openErr := image.Open(ctx, baseRef, sbom, e.opts.SourceOpts...)
	if openErr != nil {
		e.handleBaseUnreachable(ctx, logger, sbom, bundle, baseRef, openErr)
		stampStrategy(sbom, "unavailable")
		return nil
	}
	defer func() { _ = baseBundle.Close() }()

	if e.runContentStrategy(ctx, logger, sbom, bundle, baseBundle, baseRef) {
		stampStrategy(sbom, "content")
		applyChain(sbom, e.resolveChain(ctx, bundle, baseRef))
		return nil
	}

	// Tier-2 fallback: the content scan could not run (typically a
	// layer read error). Use the legacy prefix / path diff.
	diff, diffErr := layer.ComputeDiff(ctx, bundle.Image, baseBundle.Image)
	if diffErr != nil {
		logFallback(logger, "compute-diff-failed", baseRef, diffErr,
			"diff computation failed; rerun with --log-level=debug for details")
		stampUnknown(sbom)
		stampStrategy(sbom, "unavailable")
		return nil
	}

	logger.Info("basediff.diff",
		"base", baseRef,
		"mode", diffModeString(diff.Mode),
		"base_prefix", diff.BasePrefix,
		"base_paths", len(diff.BasePaths),
	)
	if diff.Mode == layer.DiffModeFallback {
		logFallback(logger, "layer-prefix-mismatch", baseRef, nil,
			"target's leading layers do not match the base image (squashed or rebased build); falling through to path-based matching")
	}

	stampOrigin(sbom, diff)
	stampStrategy(sbom, "path-fallback")
	applyChain(sbom, e.resolveChain(ctx, bundle, baseRef))
	return nil
}

// resolveChain runs DetectChain to surface the layered base
// hierarchy. Returns an empty (non-nil) BaseChain when the
// detector isn't configured (label-based / ModeExplicit paths
// reach here too — they have an immediate base ref but no
// detector). The chain is used downstream by applyChain to stamp
// chain-depth + per-level metadata. S6 Task 4 / ADR-0061.
func (e *Enricher) resolveChain(ctx context.Context, bundle *image.Bundle, baseRef string) *BaseChain {
	if e.detector == nil || e.detector.known == nil {
		// Label-based / explicit paths still get a depth=0
		// stamp + a chain:0 entry naming the immediate base, so
		// downstream consumers see a uniform shape across modes.
		return &BaseChain{Origin: &AutoDetectionResult{BaseImageRef: baseRef}}
	}
	chain, err := e.detector.DetectChain(ctx, bundle.Image)
	if err != nil || chain == nil {
		return &BaseChain{Origin: &AutoDetectionResult{BaseImageRef: baseRef}}
	}
	// If the immediate base ref came from the label-based path,
	// DetectChain may have produced an empty Levels — seed the
	// chain with the labeled ref so chain:0 metadata still lands.
	if len(chain.Levels) == 0 && baseRef != "" {
		if entry := e.detector.known.FindByRef(baseRef); entry != nil {
			chain.Levels = []*KnownBaseEntry{entry}
		}
	}
	return chain
}

// runContentStrategy executes the content-addressable diff. Returns
// true when the strategy completed (success path; the SBOM has been
// stamped); false when the caller should fall through to the legacy
// path-based diff.
//
// The strategy:
//
//  1. BaseSet ← BuildBaseSet(baseImage)  — every visible base file
//     hashed and indexed by SHA-256 plus by path.
//  2. targetHashes ← ScanTarget(targetImage) — every visible target
//     file hashed.
//  3. For each component, walk its known paths (Evidence.Locations
//     and Syft `syft:location:N:path` properties). For each path:
//     look up the target's hash → query the BaseSet. First hash
//     hit wins, the matching base path is stamped on the component
//     as forensic evidence.
//  4. When no path's hash matched but at least one target path
//     ALSO appears in the base image's path index, the file was
//     modified at the same location → Origin=base, with
//     `astinus:basediff:state=modified`.
//  5. Otherwise → Origin=app.
func (e *Enricher) runContentStrategy(ctx context.Context, logger *slog.Logger, sbom *model.SBOM, bundle, baseBundle *image.Bundle, baseRef string) bool {
	baseSet, err := contenthash.BuildBaseSet(ctx, baseBundle.Image)
	if err != nil {
		logFallback(logger, "content-base-scan-failed", baseRef, err,
			"falling back to layer-prefix / path-based diff")
		return false
	}
	targetHashes, err := contenthash.ScanTarget(ctx, bundle.Image)
	if err != nil {
		logFallback(logger, "content-target-scan-failed", baseRef, err,
			"falling back to layer-prefix / path-based diff")
		return false
	}

	stats := contentStats{}
	walkComponents(sbom.Components, func(c *model.Component) {
		c.Origin = e.classifyComponent(c, baseSet, targetHashes, &stats)
		switch c.Origin {
		case model.OriginBaseImage:
			stats.base++
		case model.OriginApplication:
			stats.app++
		default:
			stats.unknown++
		}
	})

	logger.Info("basediff.content",
		"base", baseRef,
		"base_files_indexed", baseSet.Size(),
		"base_paths_indexed", baseSet.PathCount(),
		"target_files_hashed", len(targetHashes),
		"components_total", len(sbom.Components),
		"matched_base", stats.base,
		"matched_base_modified", stats.modified,
		"app", stats.app,
		"unknown", stats.unknown,
	)
	return true
}

// contentStats counts component classifications produced by the
// content-addressable strategy. Used for the basediff.content log
// line; not surfaced into the SBOM directly.
type contentStats struct {
	base, modified, app, unknown int
}

// classifyComponent returns the Origin for c under the
// content-addressable strategy. Side effects: stamps
// `astinus:basediff:matched-base-path` (on a hash hit) or
// `astinus:basediff:state=modified` (when only the path matched).
//
// LayerInfo == nil is fine — content classification doesn't need
// layer indices, only file paths and hashes.
//
// S7 Task 2: apk components stamped by the apk-earliest path
// (ADR-0059) often have ONLY `/lib/apk/db/installed` as their
// `syft:location:N:path` — Syft's apk cataloger doesn't always
// re-stamp the binary path. After the S6-T2 path-filter strips
// the DB path (it's metadata, not the artifact), the path set is
// empty and the content strategy returned OriginUnknown — losing
// the layer-index information apk-earliest already resolved.
// Restore the lost coverage via a LayerIndex-based fallback when
// the component carries `astinus:layer:source = apk-earliest-layer`:
// LayerIndex == 0 → OriginBaseImage; > 0 → OriginApplication. The
// heuristic isn't perfect for multi-stage builds where the base
// occupies layers 0-N, but covers the dominant alpine-FROM-image
// case the run-2 benchmark exposed (C-nginx 0% → ≥ 80% target).
// ADR-0059 amendment.
func (e *Enricher) classifyComponent(c *model.Component, baseSet *contenthash.BaseSet, targetHashes map[string]string, stats *contentStats) model.Origin {
	paths := pathsForComponent(c)
	if len(paths) == 0 {
		if o, ok := classifyApkByLayerIndex(c); ok {
			return o
		}
		return model.OriginUnknown
	}

	pathInBase := false
	for _, p := range paths {
		key := layer.NormalizePath(p)
		if key == "" {
			continue
		}
		hash, ok := targetHashes[key]
		if ok {
			if ev, hit := baseSet.Contains(hash); hit {
				if c.Properties == nil {
					c.Properties = map[string]string{}
				}
				c.Properties[model.PropertyBasediffMatchedBasePath] = ev.BasePath
				return model.OriginBaseImage
			}
		}
		if baseSet.HasPath(key) {
			// Target carries a file at a path the base image also
			// uses, but the bytes don't match. Modified at the same
			// location.
			pathInBase = true
		}
	}
	if pathInBase {
		if c.Properties == nil {
			c.Properties = map[string]string{}
		}
		c.Properties[model.PropertyBasediffState] = "modified"
		stats.modified++
		return model.OriginBaseImage
	}
	return model.OriginApplication
}

// RunContentStrategyForTest is the export hook the integration
// suite uses to drive the content-addressable strategy with
// pre-built target / base bundles, bypassing image.Open. Production
// code calls runContentStrategy via Enrich; this wrapper exists
// only because the integration tests live in a separate `_test`
// package that cannot reach unexported methods.
func RunContentStrategyForTest(ctx context.Context, sbom *model.SBOM, bundle, baseBundle *image.Bundle, baseRef string) bool {
	return (&Enricher{}).runContentStrategy(ctx, slog.Default(), sbom, bundle, baseBundle, baseRef)
}

// stampStrategy records which strategy actually ran on
// sbom.Metadata.Properties. Operators consume this to tell apart
// "content match worked" from "fell back to path matching".
func stampStrategy(sbom *model.SBOM, strategy string) {
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	sbom.Metadata.Properties[model.PropertyBasediffStrategy] = strategy
}

// handleNoBase covers ModeAuto with no labels and ModeExplicit with
// no Reference. Either way every component gets Origin=unknown.
func (e *Enricher) handleNoBase(logger *slog.Logger, sbom *model.SBOM, baseRef string, err error) {
	switch {
	case err != nil:
		logFallback(logger, "base-resolve-failed", baseRef, err,
			"set --base <ref> explicitly, or add org.opencontainers.image.base.name as an OCI label on the target")
	case e.opts.Mode == ModeAuto:
		logFallback(logger, "no-base-label", "", nil,
			"target image has no org.opencontainers.image.base.* labels; rebuild with `docker buildx build --label org.opencontainers.image.base.name=...` or pass --base <ref>")
	default:
		logFallback(logger, "no-base-ref", "", nil,
			"basediff requires a base reference; pass --base <ref>")
	}
	stampUnknown(sbom)
}

// handleBaseUnreachable covers the case where the base reference IS
// known (label or explicit) but image.Open failed — typically the
// base image is not in the local daemon and the network call timed
// out / was refused. If a base digest label is set we promote to
// ModePartial with a heuristic; otherwise everything goes Unknown.
func (e *Enricher) handleBaseUnreachable(ctx context.Context, logger *slog.Logger, sbom *model.SBOM, bundle *image.Bundle, baseRef string, openErr error) {
	cfg, cfgErr := bundle.Image.ConfigFile()
	hasDigestLabel := cfgErr == nil && cfg != nil && firstNonEmpty(cfg.Config.Labels, digestLabels) != ""

	if !hasDigestLabel {
		logFallback(logger, "base-pull-failed", baseRef, openErr,
			"base image not reachable; run `docker pull "+baseRef+"` so the daemon source can read it locally, or pass --no-network and use --image archive://")
		stampUnknown(sbom)
		return
	}

	tgtLayers, layersErr := bundle.Image.Layers()
	if layersErr != nil || len(tgtLayers) < 2 {
		logFallback(logger, "base-pull-failed", baseRef, openErr,
			"base unreachable AND target layer count too small for the partial-mode heuristic; rerun with the base image in your local daemon")
		stampUnknown(sbom)
		return
	}

	// Heuristic: "the last layer is the app, every preceding layer is
	// base." Right for the dominant `FROM <base> ; COPY app /` shape.
	// Wrong for builds that lay down app code in multiple layers; in
	// those cases the operator should pre-pull the base image so the
	// real diff runs.
	prefix := len(tgtLayers) - 1
	logger.Warn("basediff.partial",
		"base", baseRef,
		"open_error", openErr.Error(),
		"layers_total", len(tgtLayers),
		"base_prefix_heuristic", prefix,
		"confidence", "low",
		"advice", "this is a heuristic; pull the base image into your local daemon or pass --base archive://... for an exact diff",
	)
	_ = ctx // reserved for future cancellation checks during partial inference
	diff := &layer.Diff{Mode: layer.DiffModePrefix, BasePrefix: prefix}
	stampOriginWithMode(sbom, diff, ModePartial)
}

// logFallback emits the structured `basediff.fallback` warn record
// the operator should look for when basediff produces no useful
// origin signal. Documented in ADR-0018.
func logFallback(logger *slog.Logger, reason, baseRef string, err error, advice string) {
	args := []any{
		"reason", reason,
		"base_ref", baseRef,
		"advice", advice,
	}
	if err != nil {
		args = append(args, "error", err.Error())
	}
	logger.Warn("basediff.fallback", args...)
}

// resolveBaseRef returns the base image reference to compare against,
// honouring Mode. Under ModeAuto, the label-based path runs first;
// when it returns empty, the S4-Task-6 content-based detector
// (os-release + bundled known-bases) attempts a confident match
// before we fall through to the no-base path. The detection method
// + identity signals are stamped on sbom.Metadata.Properties via
// stampDetectionMetadata.
func (e *Enricher) resolveBaseRef(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) (string, error) {
	switch e.opts.Mode {
	case ModeExplicit:
		if e.opts.Reference == "" {
			return "", fmt.Errorf("basediff: explicit mode requires Options.Reference")
		}
		stampDetectionMetadata(sbom, &AutoDetectionResult{
			BaseImageRef: e.opts.Reference,
			Confidence:   1.0,
			Method:       "user-explicit",
		})
		return e.opts.Reference, nil

	case ModeAuto:
		cfg, err := bundle.Image.ConfigFile()
		if err != nil {
			return "", fmt.Errorf("read image config: %w", err)
		}
		if ref := detectFromLabels(cfg); ref != "" {
			stampDetectionMetadata(sbom, &AutoDetectionResult{
				BaseImageRef: ref,
				Confidence:   1.0,
				Method:       "label",
			})
			return ref, nil
		}
		if e.detector == nil {
			stampDetectionMetadata(sbom, &AutoDetectionResult{
				FallbackReason: "content-based detection disabled",
			})
			return "", nil
		}
		result, derr := e.detector.Detect(ctx, bundle.Image)
		if derr != nil {
			return "", fmt.Errorf("basediff: content-based detection: %w", derr)
		}
		stampDetectionMetadata(sbom, result)
		return result.BaseImageRef, nil

	case ModeNone:
		return "", nil
	default:
		return "", fmt.Errorf("basediff: unknown mode %d", e.opts.Mode)
	}
}

// stampDetectionMetadata records the AutoDetector's outcome on
// sbom.Metadata.Properties so SBOM consumers can tell apart
// label-based / content-based / explicit / no-detection outcomes
// without parsing logs. Idempotent. S4 Task 6.
func stampDetectionMetadata(sbom *model.SBOM, r *AutoDetectionResult) {
	if sbom == nil || r == nil {
		return
	}
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	if r.Method != "" {
		sbom.Metadata.Properties["astinus:basediff:detection-method"] = r.Method
	}
	if r.BaseImageRef != "" {
		sbom.Metadata.Properties["astinus:basediff:detected-base"] = r.BaseImageRef
	}
	if r.Confidence > 0 {
		sbom.Metadata.Properties["astinus:basediff:detection-confidence"] =
			fmt.Sprintf("%.2f", r.Confidence)
	}
	if r.OSReleaseID != "" {
		sbom.Metadata.Properties["astinus:basediff:os-release-id"] = r.OSReleaseID
	}
	if r.OSReleaseVersionID != "" {
		sbom.Metadata.Properties["astinus:basediff:os-release-version-id"] =
			r.OSReleaseVersionID
	}
	if r.FallbackReason != "" {
		sbom.Metadata.Properties["astinus:basediff:detection-fallback-reason"] =
			r.FallbackReason
	}
}

// stampUnknown sets Origin=unknown on every component without an
// existing Origin.
func stampUnknown(sbom *model.SBOM) {
	walkComponents(sbom.Components, func(c *model.Component) {
		if c.Origin == "" {
			c.Origin = model.OriginUnknown
		}
	})
}

// stampOrigin walks every component and sets Origin from the diff.
//
// Decision tree (per component):
//
//	prefix mode  + LayerInfo.Index < BasePrefix → base
//	prefix mode  + LayerInfo.Index ≥ BasePrefix → app
//	prefix mode  + LayerInfo == nil             → unknown
//	fallback mode + any Evidence.Locations path in BasePaths → base
//	fallback mode + any syft:location:N:path  in BasePaths → base
//	fallback mode + otherwise                              → app
//
// post-Stage-13 hardening Task 3: fallback path-matching no longer
// short-circuits on LayerInfo == nil — Syft components rarely carry
// LayerInfo (Stage 3 attribution only stamps it when paths match the
// file map, which itself is fragile against Syft's location format).
// Reading paths from BOTH Evidence.Locations AND syft:location:N:path
// properties closes the same gap fixed in Task 1.
func stampOrigin(sbom *model.SBOM, diff *layer.Diff) {
	stampOriginWithMode(sbom, diff, 0)
}

// stampOriginWithMode is stampOrigin plus an optional confidence
// stamp. Used by ModePartial to mark every component low-confidence.
func stampOriginWithMode(sbom *model.SBOM, diff *layer.Diff, mode Mode) {
	walkComponents(sbom.Components, func(c *model.Component) {
		c.Origin = originFor(c, diff)
		if mode == ModePartial {
			if c.Properties == nil {
				c.Properties = map[string]string{}
			}
			c.Properties["astinus:basediff:confidence"] = "low"
		}
	})
}

func originFor(c *model.Component, diff *layer.Diff) model.Origin {
	switch diff.Mode {
	case layer.DiffModePrefix:
		// Prefix mode discriminates by LayerInfo.LayerIndex; a
		// component without LayerInfo cannot be placed.
		if c.LayerInfo == nil {
			return model.OriginUnknown
		}
		if diff.IsBaseLayer(c.LayerInfo.LayerIndex) {
			return model.OriginBaseImage
		}
		return model.OriginApplication
	case layer.DiffModeFallback:
		// Fallback mode discriminates purely by file paths. The
		// component is "base" iff ANY of its known paths is also in
		// the base image. LayerInfo is not required.
		for _, p := range pathsForComponent(c) {
			if diff.IsBasePath(p) {
				return model.OriginBaseImage
			}
		}
		// No path overlap with the base. Without LayerInfo we cannot
		// rule out unknown / app; bias toward "app" because that's
		// the more useful default for the dominant
		// `FROM base ; COPY app /` shape.
		return model.OriginApplication
	default:
		return model.OriginUnknown
	}
}

// classifyApkByLayerIndex returns the Origin for an apk component
// whose path set is empty (apk DB path was the only Syft location
// and we filtered it out). Falls through with (Unknown, false) when
// the component isn't apk OR doesn't carry the apk-earliest stamp.
// S7 Task 2 / ADR-0059 amendment.
func classifyApkByLayerIndex(c *model.Component) (model.Origin, bool) {
	if c == nil || !strings.HasPrefix(c.PURL, "pkg:apk/") {
		return "", false
	}
	if c.LayerInfo == nil {
		return "", false
	}
	if c.Properties != nil &&
		c.Properties[model.PropertyLayerSource] != "apk-earliest-layer" {
		// Components attributed by a different path (filemap-
		// last-touch, syft-location-property) don't have the
		// "earliest layer" semantic — falling back would
		// misclassify packages mass-rewritten by `apk add`.
		return "", false
	}
	if c.LayerInfo.LayerIndex == 0 {
		return model.OriginBaseImage, true
	}
	return model.OriginApplication, true
}

// pathsForComponent returns every file path the component covers,
// reading both the canonical Evidence.Locations and Syft's
// `syft:location:N:path` properties (Syft does not populate
// evidence.occurrences). Mirror of the helper in untracked/filter.go.
//
// S6 Task 2: for apk-managed components (`pkg:apk/...` PURL), the
// shared `/lib/apk/db/installed` path is filtered out — that path
// lives in BOTH the base alpine image AND every layer that runs
// `apk add` / `apk del`, so feeding it into the content-strategy's
// path/hash classifier collapses every apk row to OriginBaseImage
// (the file is in base; the bytes differ because the DB is rewritten
// on each operation, but the path-in-base check still fires). The
// apk DB path doesn't describe the artifact in any case — it's
// metadata about the package manager. ADR-0059.
func pathsForComponent(c *model.Component) []string {
	var out []string
	if c.Evidence != nil {
		for _, loc := range c.Evidence.Locations {
			if loc.Path != "" {
				out = append(out, loc.Path)
			}
		}
	}
	for k, v := range c.Properties {
		if v == "" {
			continue
		}
		if strings.HasPrefix(k, "syft:location:") && strings.HasSuffix(k, ":path") {
			out = append(out, v)
		}
	}
	return filterApkMetadataPaths(c, out)
}

// filterApkMetadataPaths drops the apk-DB path from `paths` when c
// is an apk-managed component. Returns paths unchanged for non-apk
// rows so the helper composes with other path-shapes without
// branching at the call site. S6 Task 2.
func filterApkMetadataPaths(c *model.Component, paths []string) []string {
	if c == nil || !strings.HasPrefix(c.PURL, "pkg:apk/") {
		return paths
	}
	out := paths[:0]
	for _, p := range paths {
		normalized := layer.NormalizePath(p)
		if normalized == layer.ApkInstalledPath {
			continue
		}
		out = append(out, p)
	}
	return out
}

// walkComponents applies fn to every component in comps and any
// nested SubComponents, in depth-first order.
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}

func diffModeString(m layer.DiffMode) string {
	switch m {
	case layer.DiffModePrefix:
		return "prefix"
	case layer.DiffModeFallback:
		return "fallback"
	default:
		return "unknown"
	}
}

// modeString returns a stable human label for the basediff Mode.
// Used in tests + future log lines that need to show which Mode the
// enricher actually ran in.
func modeString(m Mode) string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModeExplicit:
		return "explicit"
	case ModeNone:
		return "none"
	case ModePartial:
		return "partial"
	default:
		return "unknown"
	}
}
