package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cfgpkg "github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich"
	"github.com/psyf8t/astinus/internal/enrich/attribution"
	"github.com/psyf8t/astinus/internal/enrich/basediff"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/enrich/dedup"
	"github.com/psyf8t/astinus/internal/enrich/untracked"
	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/auth"
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
	// ExitNoNetwork is emitted when --no-network is set and the run
	// would require an outbound network call (e.g. registry pull).
	// Spec section 6.4.
	ExitNoNetwork = 30
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
	configPath   string // copied from root --config in RunE
	noNetwork    bool
	offlineDB    string
	// includeRedundant records files that sit under an already-known
	// package directory (default: skip — they belong to the existing
	// component). Debug only. post-Stage-13 hardening Task 1.
	includeRedundant bool
	// includeNoise records files classified as docs / locale /
	// metadata noise (LICENSE / README / *.h / *.map / ...).
	// Debug only.
	includeNoise bool
	// rulesFile is an optional YAML file with custom path
	// classification rules. Rules in the file are merged on top of
	// the bundled defaults — same `name` overrides the default;
	// new names are appended. PRSD-Task-1.
	rulesFile string
	// noCluster disables the filesystem-aware clustering pre-pass
	// in the untracked enricher. Default false → clustering runs.
	// PRSD-Task-3.
	noCluster bool
	// cpeMode selects the CPE resolver mode (online / offline /
	// hybrid). Default "hybrid". PRSD-Task-5.
	cpeMode string
	// nvdAPIKey is the NVD API key (env: NVD_API_KEY).
	// PRSD-Task-5.
	nvdAPIKey string
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
			// --config is a persistent root flag; pull it through.
			if f := c.Flag("config"); f != nil {
				opts.configPath = f.Value.String()
			}
			return runEnrich(c.Context(), c.OutOrStdout(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.sbomPath, "sbom", "", "Path to input SBOM, or '-' for stdin (required)")
	flags.StringVar(&opts.imageRef, "image", "", "Image reference (required)")
	flags.StringVarP(&opts.outputPath, "output", "o", "-", "Path to output SBOM, or '-' for stdout")
	flags.StringVar(&opts.outputFormat, "output-format", output.FormatSame,
		"Output format: same|cyclonedx-json|cyclonedx-xml|spdx-json|spdx-tag-value|sarif|summary")
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
	flags.BoolVar(&opts.noNetwork, "no-network", false,
		"Refuse outbound network calls (air-gapped mode)")
	flags.StringVar(&opts.offlineDB, "offline-db", "",
		"Path to offline catalogue (built via `astinus offline-db build`)")
	flags.BoolVar(&opts.includeRedundant, "include-redundant", false,
		"Record files inside already-known package directories (debug; default: skip)")
	flags.BoolVar(&opts.includeNoise, "include-noise", false,
		"Record LICENSE / README / locale / source / debug-symbol files (debug; default: skip)")
	flags.StringVar(&opts.rulesFile, "rules-file", "",
		"Path to YAML with custom path classification rules (merges over defaults)")
	flags.BoolVar(&opts.noCluster, "no-cluster", false,
		"Disable filesystem-aware clustering — record every file as a separate untracked component (debug)")
	flags.StringVar(&opts.cpeMode, "cpe-mode", "hybrid",
		"CPE resolver mode: online | offline | hybrid (default hybrid)")
	flags.StringVar(&opts.nvdAPIKey, "nvd-api-key", "",
		"NVD API key (env: NVD_API_KEY). Higher rate limit (50 req / 30s vs 5 req / 30s)")

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
	cfg, err := loadConfigIfPresent(opts.configPath)
	if err != nil {
		return newExitError(ExitInvalidArgs, err)
	}

	if opts.noNetwork && refRequiresNetwork(opts.imageRef) {
		return newExitError(ExitNoNetwork,
			fmt.Errorf("--no-network: image %q requires a registry pull; use --image with archive:// or oci:// instead",
				opts.imageRef))
	}

	tr, err := buildTransport(opts, cfg)
	if err != nil {
		return newExitError(ExitImageAccess, err)
	}

	sourceOpts := []source.Option{
		source.WithTransport(tr),
		source.WithCredentials(buildAuthChain(cfg)),
		source.WithInsecure(opts.insecure),
		source.WithPlatform(opts.platform),
		source.WithLogger(logger),
	}
	bundle, err := image.Open(ctx, opts.imageRef, sbom, sourceOpts...)
	if err != nil {
		return newExitError(ExitImageAccess, err)
	}
	defer func() { _ = bundle.Close() }()

	logger.Info("image.opened", "ref", bundle.Reference.String())

	// ── Step 3: build & run the pipeline ───────────────────────────
	enrichers, err := allEnrichers(ctx, opts, sourceOpts, tr)
	if err != nil {
		// --offline-db / matcher-chain build failures must not be
		// silently dropped — air-gapped CI must fail loudly when
		// the catalogue it pointed at can't be loaded.
		// post-stage-13 review F-011.
		return newExitError(ExitInvalidArgs, err)
	}
	pipeline := enrich.NewPipeline(logger, enrichers...)
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

	// Render then Close BOTH need their errors checked: Close on a
	// buffered writer flushes pending bytes, and a flush failure
	// (disk full, broken pipe, FS quota) means the SBOM on disk is
	// truncated. A defer-discard would ship exit code 0 with a
	// corrupt file. post-stage-13 review F-003.
	renderErr := renderer.Render(w, sbom)
	closeErr := w.Close()
	switch {
	case renderErr != nil:
		return newExitError(ExitOutputWrite, renderErr)
	case closeErr != nil:
		return newExitError(ExitOutputWrite, fmt.Errorf("close output: %w", closeErr))
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
		body, err = sbompkg.ReadAllCapped(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("sbom: read stdin: %w", err)
		}
	default:
		// File path: stat first so a 1 GB file doesn't OOM us before
		// the SBOM cap helper sees it. We still call ReadAllCapped on
		// a Reader to get a uniform error path.
		f, err := os.Open(path) //nolint:gosec // user-supplied SBOM path is trusted at the CLI boundary
		if err != nil {
			return nil, fmt.Errorf("sbom: read %s: %w", path, err)
		}
		body, err = sbompkg.ReadAllCapped(f)
		_ = f.Close()
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
//
// Per ADR-0012: the default transport reflects CLI flags + global
// config; per-registry overrides come from cfg.Registries[i].TLS.
// When the YAML carries any per-registry TLS, we wrap the default
// in transport.PerRegistry and dispatch by host.
func buildTransport(opts *enrichOptions, cfg *cfgpkg.Config) (http.RoundTripper, error) {
	def, err := transport.New(transport.Options{
		CABundle:      opts.caBundle,
		SkipTLSVerify: opts.skipTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	if cfg == nil || !cfg.HasPerRegistryTLS() {
		return def, nil
	}
	return buildPerRegistryTransport(def, cfg)
}

// buildPerRegistryTransport adds one per-host transport for every
// registry that carries TLS or Insecure config.
func buildPerRegistryTransport(def http.RoundTripper, cfg *cfgpkg.Config) (http.RoundTripper, error) {
	pr, err := transport.NewPerRegistry(def)
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.Registries {
		if r.TLS == nil && !r.Insecure && r.Proxy == "" {
			continue
		}
		o := transport.Options{}
		if r.TLS != nil {
			o.CABundle = r.TLS.CACert
			o.SkipTLSVerify = r.TLS.SkipVerify
			o.ClientCert = r.TLS.ClientCert
			o.ClientKey = r.TLS.ClientKey
		}
		if r.Proxy != "" {
			o.Proxy = r.Proxy
		}
		hostRT, err := transport.New(o)
		if err != nil {
			return nil, fmt.Errorf("transport: per-registry %q: %w", r.Host, err)
		}
		pr.Set(r.Host, hostRT)
	}
	return pr, nil
}

// loadConfigIfPresent loads cfg from path. Empty path returns nil
// (no config is fine; callers MUST nil-check the result).
func loadConfigIfPresent(path string) (*cfgpkg.Config, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // empty path legitimately means "no config"
	}
	cfg, err := cfgpkg.Load(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// buildAuthChain assembles the credential chain. Per-registry auth
// blocks become Artifactory providers (the only typed cloud provider
// today); everything else falls back to DefaultChain.
func buildAuthChain(cfg *cfgpkg.Config) auth.CredentialProvider {
	chain := auth.NewChain()
	if cfg != nil {
		for _, r := range cfg.Registries {
			if r.Auth == nil {
				continue
			}
			if p := authProviderForRegistry(r); p != nil {
				chain.Append(p)
			}
		}
	}
	for _, p := range auth.DefaultChain().Providers() {
		chain.Append(p)
	}
	return chain
}

// authProviderForRegistry maps the YAML auth.type onto a typed
// provider. Unknown types are skipped silently — DefaultChain still
// gets to try its env / docker-config providers.
func authProviderForRegistry(r cfgpkg.RegistryConfig) auth.CredentialProvider {
	if r.Auth == nil {
		return nil
	}
	switch r.Auth.Type {
	case "artifactory-token":
		return auth.NewArtifactoryProvider(auth.ArtifactoryConfig{
			Mode:     auth.ArtifactoryToken,
			Hosts:    []string{r.Host},
			TokenEnv: r.Auth.TokenEnv,
		})
	case "artifactory-api-key":
		return auth.NewArtifactoryProvider(auth.ArtifactoryConfig{
			Mode:      auth.ArtifactoryAPIKey,
			Hosts:     []string{r.Host},
			UserEnv:   r.Auth.UsernameEnv,
			APIKeyEnv: r.Auth.APIKeyEnv,
		})
	case "artifactory-oidc":
		return auth.NewArtifactoryProvider(auth.ArtifactoryConfig{
			Mode:         auth.ArtifactoryOIDC,
			Hosts:        []string{r.Host},
			OIDCTokenEnv: r.Auth.OIDCTokenEnv,
		})
	}
	return nil
}

// allEnrichers returns the canonical list of enrichers in execution
// order. Stage 12 plumbs --offline-db into both untracked
// (LocalMatcher) and cpe (LocalDictionaryResolver in the chain).
// Stage 13 prepends Software Heritage + ClearlyDefined matchers
// (cached + rate-limited) to the untracked chain when --no-network
// is unset.
//
// attribution → basediff → untracked → cpe.
//
// Returns an error when --offline-db points at a path the matcher or
// CPE-chain loader cannot read; air-gapped CI must surface that
// rather than silently fall back to default chains. post-stage-13
// review F-011.
func allEnrichers(ctx context.Context, opts *enrichOptions, sourceOpts []source.Option, tr http.RoundTripper) ([]enrich.Enricher, error) {
	logger := LoggerFrom(ctx)

	matcherChain, err := buildFingerprintMatcher(ctx, opts, tr)
	if err != nil {
		return nil, fmt.Errorf("fingerprint matcher chain: %w", err)
	}
	classifier, err := buildPathClassifier(opts.rulesFile, logger)
	if err != nil {
		return nil, err
	}
	untrackedEnricher := untracked.NewWithOptions(untracked.Options{
		Matcher: matcherChain,
		Include: untracked.IncludeMask{
			IncludeRedundant: opts.includeRedundant,
			IncludeNoise:     opts.includeNoise,
		},
		PathClassifier:    classifier,
		DisableClustering: opts.noCluster,
	})

	cpeEnricher, err := buildCPEEnricher(opts, tr, logger)
	if err != nil {
		return nil, err
	}

	return []enrich.Enricher{
		attribution.New(),
		basediff.NewWithOptions(basediffOptionsFor(opts, sourceOpts)),
		untrackedEnricher,
		cpeEnricher,
		// dedup is the finalize stage — runs LAST so PURLs / CPEs
		// added by upstream enrichers participate in the dedup key.
		// post-Stage-13 hardening Task 2.
		dedup.New(),
	}, nil
}

// buildFingerprintMatcher composes the matcher chain for the
// untracked enricher.
//
// Order:
//
//	[local from --offline-db when set]
//	  → [SWH cached+rate-limited when --no-network is unset]
//	  → matcher.Null
//
// ClearlyDefined was dropped from the default chain in
// post-stage-13 review F-012 — the Stage-13 stub always returned
// ErrNoMatch (CD is coordinate-indexed not hash-indexed; see
// ADR-0015 §7), so wiring it cost a per-lookup cache+rate-limit
// hop with zero chance of a hit. The matcher type still lives in
// the matcher package; a future PURL-based ClearlyDefined resolver
// in the cpe chain can inhabit the slot.
func buildFingerprintMatcher(_ context.Context, opts *enrichOptions, tr http.RoundTripper) (matcher.Matcher, error) {
	chain := matcher.NewChain()

	if opts.offlineDB != "" {
		local, err := buildLocalMatcher(opts.offlineDB)
		if err != nil {
			// Surface the failure — air-gapped CI must not silently
			// run with an empty local matcher when the operator
			// explicitly pointed at one.
			// post-stage-13 review F-011.
			return nil, fmt.Errorf("--offline-db %q (matcher): %w", opts.offlineDB, err)
		}
		chain.Append(local)
	}

	if !opts.noNetwork {
		// Share the configured transport (corporate CA / mTLS /
		// retry / UA stamp) with the matcher HTTP clients. Falling
		// back to a bare http.DefaultTransport inside an explicit
		// http.Client wrapped only the request timeout —
		// post-stage-13 review F-009.
		if tr == nil {
			tr = http.DefaultTransport
		}
		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		// Bumped from defaults (5/s burst 10) to 20/s burst 30. The
		// untracked enricher's category filter (Task 4) caps total
		// matcher lookups at a few hundred per scan, so even at
		// 20 req/s we never sustain the rate long enough to risk a
		// SWH ban. Drops wall-clock under 1 minute on the reference
		// 1 GiB image (was 25+ min at the original 5/s).
		// post-Stage-13 hardening Task 4.
		swh := matcher.NewCached(
			matcher.NewRateLimited(
				matcher.NewSWHMatcher("", client),
				matcher.RateLimitOptions{Burst: 30, PerSecond: 20},
			),
			matcher.CacheOptions{},
		)
		chain.Append(swh)
		// ClearlyDefined intentionally NOT wired into the default
		// chain. Per ADR-0015 §7 the matcher is a coordinate-indexed
		// stub that always returns ErrNoMatch; keeping it on the
		// chain incurred a cache + rate-limit hop per untracked
		// lookup with zero chance of a hit. The matcher type stays
		// in the package so a future PURL-based ClearlyDefined
		// resolver in the cpe chain can inhabit the slot.
		// post-stage-13 review F-012.
	}

	chain.Append(matcher.Null)
	return chain, nil
}

// buildLocalMatcher loads the offline-db catalogue into a
// fingerprint matcher.
func buildLocalMatcher(offlineDB string) (matcher.Matcher, error) {
	m := matcher.NewLocalMatcher()
	if err := m.LoadFromDir(offlineDB); err != nil {
		return nil, err
	}
	return m, nil
}

// refRequiresNetwork reports whether ref points at something that
// needs an outbound network call to load.
//
// Heuristic: archive://, oci://, docker-daemon://, podman-daemon://,
// or a path that exists on disk → no network. Everything else →
// registry pull → network.
func refRequiresNetwork(ref string) bool {
	if ref == "" {
		return false
	}
	for _, scheme := range []string{
		"archive://", "oci://", "docker-daemon://", "podman-daemon://",
	} {
		if strings.HasPrefix(ref, scheme) {
			return false
		}
	}
	if _, err := os.Stat(ref); err == nil {
		return false
	}
	return true
}

// basediffOptionsFor maps the CLI's --base flag to basediff.Options.
//
//	auto             → ModeAuto (default)
//	none             → ModeNone (skip)
//	anything else    → ModeExplicit, with the value as the reference
//
// buildCPEEnricher composes the CPE enricher's resolver chain
// based on operator-supplied flags + env vars.
//
// Mode handling:
//
//   - `--cpe-mode offline` builds a chain of offline-only Sources
//     (PatternMatcher + LocalDict + Heuristic). Guaranteed zero
//     outbound HTTP.
//   - `--cpe-mode online` adds NVD API + ClearlyDefined Sources.
//     `--nvd-api-key` (or env NVD_API_KEY) bumps NVD's rate limit.
//   - `--cpe-mode hybrid` is offline-first, online for the long
//     tail. Default when the operator passed no flag.
//   - `--no-network` overrides --cpe-mode and forces offline mode.
//
// PRSD-Task-5.
func buildCPEEnricher(opts *enrichOptions, tr http.RoundTripper, logger *slog.Logger) (*cpe.Enricher, error) {
	mode := cpesources.Mode(strings.ToLower(strings.TrimSpace(opts.cpeMode)))
	if !mode.IsKnown() {
		mode = cpesources.ModeHybrid
	}
	if opts.noNetwork {
		mode = cpesources.ModeOffline
	}

	srcs := []cpesources.Source{
		cpesources.NewPatternMatcher(),
	}
	if opts.offlineDB != "" {
		local := cpe.NewLocalDictionaryResolver()
		local.SetLogger(logger)
		if err := local.LoadFromDir(opts.offlineDB); err != nil {
			return nil, fmt.Errorf("--offline-db %q (cpe local dict): %w", opts.offlineDB, err)
		}
		if s := cpesources.NewLocalDict(local); s != nil {
			srcs = append(srcs, s)
		}
	}
	if mode != cpesources.ModeOffline {
		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		nvdKey := opts.nvdAPIKey
		if nvdKey == "" {
			nvdKey = os.Getenv("NVD_API_KEY")
		}
		srcs = append(srcs,
			cpesources.NewNVDAPI(nvdKey, client),
			cpesources.NewClearlyDefined(client),
		)
	}
	srcs = append(srcs, cpesources.NewHeuristic())

	resolver := cpesources.NewMultiSource(cpesources.Options{
		Mode:    mode,
		Sources: srcs,
		Logger:  logger,
	})
	logger.Info("cpe.resolver.configured",
		"mode", string(mode),
		"sources", len(resolver.Sources()),
		"nvd_authenticated", opts.nvdAPIKey != "" || os.Getenv("NVD_API_KEY") != "")
	return cpe.NewWithResolver(resolver), nil
}

// buildPathClassifier loads the bundled default rules and (when
// --rules-file was passed) merges the operator's overrides on top.
// Returns a nil classifier if the merged rule set fails to compile —
// today that's surfaced as an error so a misconfigured rules file
// never silently degrades the scan.
//
// PRSD-Task-1.
func buildPathClassifier(rulesPath string, logger *slog.Logger) (*pathclassifier.Classifier, error) {
	defaults, err := pathclassifier.LoadDefault()
	if err != nil {
		return nil, fmt.Errorf("path classifier: load default rules: %w", err)
	}
	rules := defaults
	if rulesPath != "" {
		custom, err := pathclassifier.LoadFromPath(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("--rules-file %q: %w", rulesPath, err)
		}
		rules = pathclassifier.Merge(defaults, custom)
		logger.Info("untracked.rules.loaded",
			"file", rulesPath,
			"defaults", len(defaults),
			"custom", len(custom),
			"merged", len(rules))
	}
	c, err := pathclassifier.New(rules)
	if err != nil {
		return nil, fmt.Errorf("path classifier: compile rules: %w", err)
	}
	return c, nil
}

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
