package basediff

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

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
}

// Enricher implements enrich.Enricher.
type Enricher struct {
	opts Options
}

// New returns an Enricher with default options (Mode=Auto).
func New() *Enricher { return NewWithOptions(Options{}) }

// NewWithOptions returns an Enricher with the supplied options.
func NewWithOptions(o Options) *Enricher { return &Enricher{opts: o} }

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Enrich implements enrich.Enricher.
//
// Always returns nil — basediff is best-effort. Failures (no
// detected base, base unreachable, etc.) downgrade to "everyone is
// unknown" or, when target labels carry a base.digest, the partial
// mode heuristic. post-Stage-13 hardening Task 3.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("basediff: missing sbom/bundle/image")
	}

	logger := slog.Default()

	if e.opts.Mode == ModeNone {
		return nil
	}

	baseRef, err := e.resolveBaseRef(bundle)
	if err != nil || baseRef == "" {
		e.handleNoBase(logger, sbom, baseRef, err)
		return nil
	}

	baseBundle, openErr := image.Open(ctx, baseRef, sbom, e.opts.SourceOpts...)
	if openErr != nil {
		e.handleBaseUnreachable(ctx, logger, sbom, bundle, baseRef, openErr)
		return nil
	}
	defer func() { _ = baseBundle.Close() }()

	diff, diffErr := layer.ComputeDiff(ctx, bundle.Image, baseBundle.Image)
	if diffErr != nil {
		logFallback(logger, "compute-diff-failed", baseRef, diffErr,
			"diff computation failed; rerun with --log-level=debug for details")
		stampUnknown(sbom)
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
	return nil
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
// honouring Mode.
func (e *Enricher) resolveBaseRef(bundle *image.Bundle) (string, error) {
	switch e.opts.Mode {
	case ModeExplicit:
		if e.opts.Reference == "" {
			return "", fmt.Errorf("basediff: explicit mode requires Options.Reference")
		}
		return e.opts.Reference, nil
	case ModeAuto:
		cfg, err := bundle.Image.ConfigFile()
		if err != nil {
			return "", fmt.Errorf("read image config: %w", err)
		}
		return detectFromLabels(cfg), nil
	case ModeNone:
		return "", nil
	default:
		return "", fmt.Errorf("basediff: unknown mode %d", e.opts.Mode)
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

// pathsForComponent returns every file path the component covers,
// reading both the canonical Evidence.Locations and Syft's
// `syft:location:N:path` properties (Syft does not populate
// evidence.occurrences). Mirror of the helper in untracked/filter.go.
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
