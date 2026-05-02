package basediff

import (
	"context"
	"fmt"
	"log/slog"

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
// unknown" plus a warning log.
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
		if err != nil {
			logger.Warn("basediff: base image resolution failed",
				"error", err.Error())
		} else {
			logger.Info("basediff: no base image label found; marking all components Origin=unknown")
		}
		stampUnknown(sbom)
		return nil
	}

	baseBundle, err := image.Open(ctx, baseRef, sbom, e.opts.SourceOpts...)
	if err != nil {
		logger.Warn("basediff: cannot open base image",
			"base", baseRef,
			"error", err.Error(),
		)
		stampUnknown(sbom)
		return nil
	}
	defer func() { _ = baseBundle.Close() }()

	diff, err := layer.ComputeDiff(ctx, bundle.Image, baseBundle.Image)
	if err != nil {
		logger.Warn("basediff: ComputeDiff failed",
			"base", baseRef,
			"error", err.Error(),
		)
		stampUnknown(sbom)
		return nil
	}

	logger.Info("basediff: diff computed",
		"base", baseRef,
		"mode", diffModeString(diff.Mode),
		"base_prefix", diff.BasePrefix,
	)

	stampOrigin(sbom, diff)
	return nil
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
// Decision tree:
//
//	c.LayerInfo == nil          → unknown
//	prefix mode + Index < N     → base
//	prefix mode + Index ≥ N     → app
//	fallback mode + path in base→ base
//	fallback mode + otherwise   → app
func stampOrigin(sbom *model.SBOM, diff *layer.Diff) {
	walkComponents(sbom.Components, func(c *model.Component) {
		c.Origin = originFor(c, diff)
	})
}

func originFor(c *model.Component, diff *layer.Diff) model.Origin {
	if c.LayerInfo == nil {
		return model.OriginUnknown
	}
	switch diff.Mode {
	case layer.DiffModePrefix:
		if diff.IsBaseLayer(c.LayerInfo.LayerIndex) {
			return model.OriginBaseImage
		}
		return model.OriginApplication
	case layer.DiffModeFallback:
		if c.Evidence != nil {
			for _, loc := range c.Evidence.Locations {
				if diff.IsBasePath(loc.Path) {
					return model.OriginBaseImage
				}
			}
		}
		return model.OriginApplication
	default:
		return model.OriginUnknown
	}
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
