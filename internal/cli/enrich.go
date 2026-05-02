package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/psyf8t/astinus/internal/enrich"
	"github.com/psyf8t/astinus/internal/enrich/attribution"
	"github.com/psyf8t/astinus/internal/enrich/basediff"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/untracked"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/source"
	"github.com/psyf8t/astinus/internal/image/transport"
	"github.com/psyf8t/astinus/internal/output"
	sbompkg "github.com/psyf8t/astinus/internal/sbom"
	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/sbom/spdx"
)

// Enrich exit codes — extends the spec section 6.4 enumeration.
const (
	ExitSBOMRead    = 3
	ExitImageAccess = 4
	ExitEnrich      = 5
	ExitOutputWrite = 6
)

// enrichOptions are bound to flags by newEnrichCommand.
type enrichOptions struct {
	sbomPath     string
	imageRef     string
	outputPath   string
	outputFormat string
	enable       []string
	disable      []string
	platform     string
	insecure     bool
	caBundle     string
	skipTLS      bool
	base         string // "auto" | "none" | <ref>
}

func newEnrichCommand() *cobra.Command {
	opts := &enrichOptions{}
	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Enrich an SBOM with information from a container image",
		Long: `Read an SBOM (CycloneDX or SPDX) and a container image, then
write back an SBOM augmented with layer attribution, base-image diff,
untracked components, and CPE identifiers.

Stage 3 ships only the layer-attribution enricher; subsequent stages
add the others.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runEnrich(c.Context(), c.OutOrStdout(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.sbomPath, "sbom", "", "Path to input SBOM, or '-' for stdin (required)")
	flags.StringVar(&opts.imageRef, "image", "", "Image reference (required)")
	flags.StringVarP(&opts.outputPath, "output", "o", "-", "Path to output SBOM, or '-' for stdout")
	flags.StringVar(&opts.outputFormat, "output-format", output.FormatSame,
		"Output format: same|cyclonedx-json|cyclonedx-xml|spdx-json|spdx-tag-value")
	flags.StringSliceVar(&opts.enable, "enable", nil,
		"Comma-separated list of enrichers to run (default: all known)")
	flags.StringSliceVar(&opts.disable, "disable", nil,
		"Comma-separated list of enrichers to skip")
	flags.StringVar(&opts.platform, "platform", "",
		"Platform constraint for multi-arch images (e.g. linux/arm64)")
	flags.BoolVar(&opts.insecure, "insecure", false, "Allow plaintext HTTP to the registry")
	flags.BoolVar(&opts.skipTLS, "skip-tls-verify", false,
		"Skip TLS verification (NOT recommended)")
	flags.StringVar(&opts.caBundle, "ca-cert", "", "Path to a custom CA bundle (PEM)")
	flags.StringVar(&opts.base, "base", "auto",
		"Base image to diff against: auto|none|<ref>")

	_ = cmd.MarkFlagRequired("sbom")
	_ = cmd.MarkFlagRequired("image")
	return cmd
}

func runEnrich(ctx context.Context, _ io.Writer, opts *enrichOptions) error {
	logger := LoggerFrom(ctx)

	// ── Step 1: read & parse the SBOM ──────────────────────────────
	sbom, err := loadSBOM(opts.sbomPath)
	if err != nil {
		return newExitError(ExitSBOMRead, err)
	}
	logger.Info("sbom.loaded",
		"format", sbom.SourceFormat,
		"components", len(sbom.Components),
	)

	// ── Step 2: open the image ─────────────────────────────────────
	tr, err := buildTransport(opts)
	if err != nil {
		return newExitError(ExitImageAccess, err)
	}

	sourceOpts := []source.Option{
		source.WithTransport(tr),
		source.WithInsecure(opts.insecure),
		source.WithPlatform(opts.platform),
	}
	bundle, err := image.Open(ctx, opts.imageRef, sbom, sourceOpts...)
	if err != nil {
		return newExitError(ExitImageAccess, err)
	}
	defer func() { _ = bundle.Close() }()

	logger.Info("image.opened", "ref", bundle.Reference.String())

	// ── Step 3: build & run the pipeline ───────────────────────────
	pipeline := enrich.NewPipeline(logger, allEnrichers(opts, sourceOpts)...)
	pipeline = enrich.NewPipeline(logger, enrich.Filter(
		pipeline.Enrichers(),
		stringSliceToSet(opts.enable),
		stringSliceToSet(opts.disable),
	)...)

	if err := pipeline.Run(ctx, sbom, bundle); err != nil {
		return newExitError(ExitEnrich, err)
	}

	// ── Step 4: render & write the output ──────────────────────────
	formatName := opts.outputFormat
	if formatName == output.FormatSame {
		formatName = output.ResolveSame(sbom.SourceFormat)
	}
	renderer, err := output.Get(formatName, output.Options{Pretty: true})
	if err != nil {
		return newExitError(ExitInvalidArgs, err)
	}

	w, err := output.Open(opts.outputPath)
	if err != nil {
		return newExitError(ExitOutputWrite, err)
	}
	defer func() { _ = w.Close() }()

	if err := renderer.Render(w, sbom); err != nil {
		return newExitError(ExitOutputWrite, err)
	}
	logger.Info("enrich.done",
		"output", opts.outputPath,
		"format", formatName,
	)
	return nil
}

// loadSBOM reads from stdin (path == "-") or a file, auto-detects the
// format, and returns the canonical SBOM.
func loadSBOM(path string) (*model.SBOM, error) {
	var (
		body []byte
		err  error
	)
	switch path {
	case "":
		return nil, errors.New("sbom: empty path")
	case output.StdoutPath: // "-" reused for stdin
		body, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("sbom: read stdin: %w", err)
		}
	default:
		body, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("sbom: read %s: %w", path, err)
		}
	}

	format, err := sbompkg.DetectBytes(body)
	if err != nil {
		return nil, err
	}
	switch format {
	case model.FormatCycloneDXJSON, model.FormatCycloneDXXML:
		return cyclonedx.ReadBytes(body, format)
	case model.FormatSPDXJSON, model.FormatSPDXTagValue:
		return spdx.ReadBytes(body, format)
	default:
		return nil, fmt.Errorf("sbom: unrecognised format")
	}
}

// buildTransport returns the http.RoundTripper configured for this
// enrich invocation.
func buildTransport(opts *enrichOptions) (http.RoundTripper, error) {
	rt, err := transport.New(transport.Options{
		CABundle:      opts.caBundle,
		SkipTLSVerify: opts.skipTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	return rt, nil
}

// allEnrichers returns the canonical list of enrichers in execution
// order. Stage 6 completes the chain:
// attribution → basediff → untracked → cpe.
func allEnrichers(opts *enrichOptions, sourceOpts []source.Option) []enrich.Enricher {
	return []enrich.Enricher{
		attribution.New(),
		basediff.NewWithOptions(basediffOptionsFor(opts, sourceOpts)),
		untracked.New(),
		cpe.New(),
	}
}

// basediffOptionsFor maps the CLI's --base flag to basediff.Options.
//
//	auto             → ModeAuto (default)
//	none             → ModeNone (skip)
//	anything else    → ModeExplicit, with the value as the reference
func basediffOptionsFor(opts *enrichOptions, sourceOpts []source.Option) basediff.Options {
	switch strings.TrimSpace(opts.base) {
	case "", "auto":
		return basediff.Options{Mode: basediff.ModeAuto, SourceOpts: sourceOpts}
	case "none":
		return basediff.Options{Mode: basediff.ModeNone}
	default:
		return basediff.Options{
			Mode:       basediff.ModeExplicit,
			Reference:  opts.base,
			SourceOpts: sourceOpts,
		}
	}
}

// stringSliceToSet turns a comma-separated CLI slice into a set,
// returning nil for an empty/no-op input so callers can use len()==0
// to mean "no filter".
func stringSliceToSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out[s] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
