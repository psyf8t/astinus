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
	"github.com/psyf8t/astinus/internal/enrich/compliance"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
	"github.com/psyf8t/astinus/internal/enrich/dedup"
	enrichextractor "github.com/psyf8t/astinus/internal/enrich/extractor"
	"github.com/psyf8t/astinus/internal/enrich/lifecycle"
	registryenrich "github.com/psyf8t/astinus/internal/enrich/registry"
	registrysources "github.com/psyf8t/astinus/internal/enrich/registry/sources"
	"github.com/psyf8t/astinus/internal/enrich/syftprefilter"
	"github.com/psyf8t/astinus/internal/enrich/untracked"
	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/auth"
	"github.com/psyf8t/astinus/internal/image/source"
	"github.com/psyf8t/astinus/internal/image/transport"
	"github.com/psyf8t/astinus/internal/output"
	"github.com/psyf8t/astinus/internal/policy"
	compliancepolicy "github.com/psyf8t/astinus/internal/policy/builtin/compliance"
	sbompkg "github.com/psyf8t/astinus/internal/sbom"
	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/sbom/spdx"
	"github.com/psyf8t/astinus/internal/sign"
	"github.com/psyf8t/astinus/internal/telemetry"
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
	// ExitComplianceFail is emitted when --fail-on names a severity
	// floor and at least one compliance finding meets that floor.
	// PRSD-Task-7.
	ExitComplianceFail = 40
	// ExitSigning is emitted when `--sign-with` was set but the
	// signing step failed (cosign missing, key invalid, signing
	// returned non-zero, etc.). Non-fatal: the SBOM file is still
	// written before signing runs, so the operator keeps the
	// artefact. S3 Task 6.
	ExitSigning = 50
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
	// includeRejectedCPE makes the cpe enricher emit
	// `astinus:cpe:rejected:N` properties for candidates that
	// scored below the alternative-min threshold (debug surface).
	// Default false; rejected candidates always land in the debug
	// log regardless. S3 Task 0 / ADR-0029.
	includeRejectedCPE bool
	// complianceConfig is an optional YAML file with severity
	// overrides for the compliance enricher's per-ecosystem
	// SeverityPolicy (S3 Task 2 / ADR-0031). Empty path = bundled
	// defaults only.
	complianceConfig string
	// noSyftPrefilter disables the pre-pipeline syftprefilter
	// stage. Default false (filter on). Forensic-mode operators
	// who need every Syft `type=file` Component preserved set
	// this to true. S3 Task 3 / ADR-0032.
	noSyftPrefilter bool
	// noRegistry disables the package-registry enrichment stage.
	// Default false (enrichment on; honoured per --no-network and
	// per-source NetworkOK). S3 Task 4 / ADR-0033.
	noRegistry bool
	// mirrorsConfig is an optional YAML file with package-registry
	// mirror config (npm/PyPI/Maven/etc.). Empty path = no
	// mirrors, fall through to public upstreams.
	mirrorsConfig string
	// registryCacheDir enables a layered (memory + on-disk) cache
	// for registry metadata. Empty path = memory-only.
	registryCacheDir string
	// registryCacheTTL is the per-entry TTL for the disk cache.
	// 0 disables expiry.
	registryCacheTTL time.Duration
	// noLifecycle disables the lifecycle / EOL enrichment stage.
	// Default off (enrichment on). S3 Task 5 / ADR-0035.
	noLifecycle bool
	// lifecycleMode is online | offline | hybrid (default).
	// Hybrid tries endoflife.date first, falls back to bundled.
	// `--no-network` overrides to offline.
	lifecycleMode string
	// lifecycleSnapshot points at an operator-supplied JSON
	// snapshot file (refreshed via `astinus lifecycle update`).
	// Empty path uses the embedded seed snapshot.
	lifecycleSnapshot string
	// signWith selects the signing flow: "" (off, default) /
	// "cosign-key" / "cosign-keyless". S3 Task 6 / ADR-0036.
	signWith string
	// signingKey is the Cosign private-key path (cosign-key
	// mode).
	signingKey string
	// signingKeyPasswordEnv is the env var holding the key's
	// password. Default `COSIGN_PASSWORD` (cosign's own
	// convention).
	signingKeyPasswordEnv string
	// attachToImage is the OCI ref to attach the in-toto
	// attestation to (e.g. `myorg/img:v1`). Empty = produce a
	// detached signature only.
	attachToImage string
	// signatureOutput is the path where cosign writes the
	// detached signature (sign-blob mode).
	signatureOutput string
	// rekorURL / fulcioURL / tufMirror are the corporate
	// Sigstore overrides. Empty = use Sigstore public.
	rekorURL  string
	fulcioURL string
	tufMirror string
	// cosignPath overrides the `cosign` lookup. Useful for
	// custom installs and for the test harness.
	cosignPath string
	// failOn is the compliance-finding severity gate. Empty
	// means "never fail on compliance findings"; non-empty
	// values are one of `critical`, `high`, `medium`, `low`,
	// `info`. PRSD-Task-7.
	failOn string
	// metricsOutput controls how the in-process Prometheus
	// registry is exposed at the end of the run. Forms:
	//
	//   ""                     → metrics disabled (default)
	//   "stdout" / "stderr"    → write Prometheus text exposition
	//   "file:/path/to/file"   → write to the given file
	//
	// Bound by --metrics-output. PRSD-Task-8.
	metricsOutput string
	// tracingEndpoint sets the OpenTelemetry collector endpoint.
	// Empty disables tracing (NoopTracer is used). Today the
	// endpoint is recorded but no exporter is wired in — see
	// ADR-0026 for the OTel deferral. PRSD-Task-8.
	tracingEndpoint string
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
	flags.BoolVar(&opts.includeRejectedCPE, "include-rejected-cpe", false,
		"Emit astinus:cpe:rejected:N properties for CPE candidates "+
			"that failed the confidence threshold (debug; default off — "+
			"rejected candidates always appear in the cpe.rejected debug log).")
	flags.StringVar(&opts.complianceConfig, "compliance-config", "",
		"Path to a YAML file with compliance severity overrides "+
			"(per ecosystem / component_type). Default: bundled per-ecosystem "+
			"policy. See ADR-0031 for the schema.")
	flags.BoolVar(&opts.noSyftPrefilter, "no-syft-prefilter", false,
		"Disable Syft baseline noise filtering. Keep every type=file "+
			"Component the upstream SBOM produced (forensic mode; the "+
			"default filter drops /etc/cron.d/, /etc/apt/, /etc/pam.d/ "+
			"noise via the bundled path-classifier rules). See ADR-0032.")
	flags.BoolVar(&opts.noRegistry, "no-registry", false,
		"Disable package-registry enrichment. Default off — Astinus "+
			"fetches license / supplier / homepage / repository / hashes "+
			"from npm / PyPI / Maven / Go module proxy (and stub-registered "+
			"cargo / gem / nuget / deb / apk / repology / ecosyste-ms; "+
			"see ADR-0033 §6 for the deferred-source list).")
	flags.StringVar(&opts.mirrorsConfig, "mirrors-config", "",
		"Path to a YAML file with package-registry mirror config "+
			"(per-ecosystem mirror URL + auth + TLS). Default: no "+
			"mirrors, fall through to public upstreams. See ADR-0034 "+
			"for the schema.")
	flags.StringVar(&opts.registryCacheDir, "registry-cache-dir", "",
		"Directory for the registry-metadata disk cache. Default "+
			"memory-only (per-process). Set to enable a layered cache "+
			"that survives restarts.")
	flags.DurationVar(&opts.registryCacheTTL, "registry-cache-ttl",
		7*24*time.Hour,
		"Per-entry TTL for the registry-cache-dir cache. 0 disables "+
			"expiry. Default 7 days (NPM/PyPI/Maven entries change rarely "+
			"once published).")
	flags.BoolVar(&opts.noLifecycle, "no-lifecycle", false,
		"Disable lifecycle / EOL enrichment. Default off — Astinus "+
			"stamps astinus:lifecycle:* properties on OS / runtime "+
			"Components (Node, Python, Go, Java, Debian, Ubuntu, "+
			"Alpine, Postgres, MySQL, Redis, Kubernetes, Docker, …) "+
			"from endoflife.date data plus a bundled offline snapshot. "+
			"See ADR-0035.")
	flags.StringVar(&opts.lifecycleMode, "lifecycle-mode", "hybrid",
		"Lifecycle resolver mode: online | offline | hybrid (default "+
			"hybrid — endoflife.date first, bundled fallback). "+
			"`--no-network` overrides to offline.")
	flags.StringVar(&opts.lifecycleSnapshot, "lifecycle-snapshot", "",
		"Path to a custom endoflife.date snapshot JSON file (overrides "+
			"the embedded seed). Refresh via `astinus lifecycle update`.")
	flags.StringVar(&opts.signWith, "sign-with", "",
		"Sign the rendered SBOM. Values: cosign-key | cosign-keyless. "+
			"Empty (default) disables signing. Wraps the cosign "+
			"subprocess — install cosign to use. See ADR-0036.")
	flags.StringVar(&opts.signingKey, "signing-key", "",
		"Path to a Cosign private key (cosign-key mode).")
	flags.StringVar(&opts.signingKeyPasswordEnv, "signing-key-password-env",
		"COSIGN_PASSWORD",
		"Env var holding the cosign private-key password. Default "+
			"COSIGN_PASSWORD (cosign's own convention).")
	flags.StringVar(&opts.attachToImage, "attach-to-image", "",
		"Attach the in-toto attestation to this OCI image reference "+
			"(e.g. ghcr.io/org/img:v1). Empty = detached signature only.")
	flags.StringVar(&opts.signatureOutput, "signature-output", "",
		"Path to write the detached cosign signature (sign-blob mode). "+
			"Required when --attach-to-image is empty.")
	flags.StringVar(&opts.rekorURL, "rekor-url", "",
		"Corporate Rekor transparency-log URL. Empty = Sigstore public.")
	flags.StringVar(&opts.fulcioURL, "fulcio-url", "",
		"Corporate Fulcio CA URL. Empty = Sigstore public.")
	flags.StringVar(&opts.tufMirror, "tuf-mirror", "",
		"TUF root mirror URL for air-gapped Sigstore. Empty = Sigstore "+
			"public.")
	flags.StringVar(&opts.cosignPath, "cosign-path", "",
		"Override the cosign binary lookup (default: PATH).")
	flags.StringVar(&opts.failOn, "fail-on", "",
		"Exit non-zero when any compliance finding meets this severity: critical | high | medium | low | info (default: never fail)")
	flags.StringVar(&opts.metricsOutput, "metrics-output", "",
		"Where to emit Prometheus text-format metrics at end of run: stdout | stderr | file:/path (default: disabled)")
	flags.StringVar(&opts.tracingEndpoint, "tracing-endpoint", "",
		"OpenTelemetry collector endpoint (default: disabled — see ADR-0026)")

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
	// Pass len(sbom.Components) so the CPE enricher can skip the
	// NVD API source up-front when the workload would wedge under
	// the anonymous rate limit. ADR-0028.
	enrichers, err := allEnrichers(ctx, opts, sourceOpts, tr, len(sbom.Components))
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

	// PRSD-Task-8: opt-in observability. Metrics + tracing only
	// fire when the operator passes the corresponding flag; the
	// no-op tracer is zero-cost and the metrics registry is nil.
	registry := configureMetrics(opts.metricsOutput, pipeline)
	configureTracing(opts.tracingEndpoint, pipeline, logger)

	if err := pipeline.Run(ctx, sbom, bundle); err != nil {
		// Even on failure we want to write any metrics already
		// observed — operators dashboarding error rates need the
		// counter increment to land. Errors during export are
		// logged but do not mask the original Run error.
		writeMetrics(opts.metricsOutput, registry, logger)
		return newExitError(ExitEnrich, err)
	}
	writeMetrics(opts.metricsOutput, registry, logger)

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
	return runPostRenderHooks(ctx, opts, sbom, logger, formatName)
}

// runPostRenderHooks fires the operator-visible side effects that
// must happen AFTER the SBOM file is on disk: optional Cosign
// signing (S3 Task 6) and the `--fail-on` compliance gate
// (PRSD-Task-7). Both produce non-zero exit codes; both leave the
// SBOM artefact in place.
func runPostRenderHooks(ctx context.Context, opts *enrichOptions, sbom *model.SBOM, logger *slog.Logger, formatName string) error {
	if exitErr := runSigningStep(ctx, opts, logger, formatName); exitErr != nil {
		return exitErr
	}
	if exitErr := evaluateComplianceGate(ctx, opts, sbom, logger); exitErr != nil {
		return exitErr
	}
	return nil
}

// runSigningStep runs cosign over the rendered SBOM file when
// `--sign-with` is set. No-op for the default empty value. Errors
// (cosign missing, key invalid, signing returned non-zero) are
// surfaced as ExitSigning with the underlying error preserved —
// operators see exactly what cosign complained about.
//
// Refuses to sign when output went to stdout (`--output -`) — the
// signature MUST cover the byte content the operator hands
// downstream, and stdout has already been flushed by the time we
// get here.
func runSigningStep(ctx context.Context, opts *enrichOptions, logger *slog.Logger, formatName string) *exitError {
	mode := sign.Mode(opts.signWith)
	if mode == sign.ModeNone {
		return nil
	}
	if !mode.IsKnown() {
		return newExitError(ExitInvalidArgs,
			fmt.Errorf("--sign-with: unknown mode %q (want cosign-key | cosign-keyless)", opts.signWith))
	}
	if opts.outputPath == "-" || opts.outputPath == "" {
		return newExitError(ExitInvalidArgs,
			fmt.Errorf("--sign-with requires a real --output path (cannot sign stdout)"))
	}
	body, err := os.ReadFile(opts.outputPath) //nolint:gosec // operator-supplied output path
	if err != nil {
		return newExitError(ExitOutputWrite,
			fmt.Errorf("read SBOM for signing: %w", err))
	}
	signOpts := sign.SignOptions{
		Format:         formatName,
		AttachToImage:  opts.attachToImage,
		OutputFile:     opts.signatureOutput,
		KeyPath:        opts.signingKey,
		KeyPasswordEnv: opts.signingKeyPasswordEnv,
		RekorURL:       opts.rekorURL,
		FulcioURL:      opts.fulcioURL,
		TUFMirror:      opts.tufMirror,
		CABundle:       opts.caBundle,
	}
	if err := signOpts.Validate(mode); err != nil {
		return newExitError(ExitInvalidArgs, err)
	}
	signer, err := sign.NewCosignSigner(sign.CosignOptions{
		CosignPath: opts.cosignPath,
		Logger:     logger,
	})
	if err != nil {
		return newExitError(ExitSigning, err)
	}
	artifact, err := signer.Sign(ctx, body, signOpts)
	if err != nil {
		return newExitError(ExitSigning, err)
	}
	logger.Info("sign.complete",
		"signer", signer.Name(),
		"format", artifact.Format,
		"oci_ref", artifact.OCIReference,
		"output_file", opts.signatureOutput,
		"predicate_uri", artifact.PredicateURI,
		"signed_at", artifact.SignedAt.Format(time.RFC3339))
	return nil
}

// evaluateComplianceGate enforces `--fail-on <severity>`. Returns
// nil when the flag was empty or no finding crossed the threshold;
// otherwise returns a non-zero ExitComplianceFail error.
func evaluateComplianceGate(ctx context.Context, opts *enrichOptions, sbom *model.SBOM, logger *slog.Logger) error {
	if opts.failOn == "" {
		return nil
	}
	floor, ok := policy.ParseSeverity(strings.ToLower(strings.TrimSpace(opts.failOn)))
	if !ok {
		return newExitError(ExitInvalidArgs, fmt.Errorf("--fail-on: unknown severity %q", opts.failOn))
	}
	enricher := compliance.New()
	findings := enricher.Findings(ctx, sbom)
	hits := 0
	for _, f := range findings {
		if f.Severity.AtLeast(floor) {
			hits++
		}
	}
	if hits == 0 {
		logger.Info("compliance.gate.passed",
			"floor", floor.String(),
			"findings_total", len(findings))
		return nil
	}
	logger.Warn("compliance.gate.failed",
		"floor", floor.String(),
		"findings_at_or_above_floor", hits,
		"findings_total", len(findings))
	return newExitError(ExitComplianceFail,
		fmt.Errorf("compliance: %d finding(s) at or above %q severity (run with --fail-on=\"\" to disable the gate)",
			hits, floor.String()))
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
func allEnrichers(ctx context.Context, opts *enrichOptions, sourceOpts []source.Option, tr http.RoundTripper, componentCount int) ([]enrich.Enricher, error) {
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

	cpeEnricher, err := buildCPEEnricher(opts, tr, logger, componentCount)
	if err != nil {
		return nil, err
	}

	severityPolicy, err := compliancepolicy.LoadSeverityPolicyFromFile(opts.complianceConfig)
	if err != nil {
		return nil, err
	}
	complianceEnricher := compliance.New().WithSeverityPolicy(severityPolicy)

	// S3 Task 3: pre-pipeline noise filter for Syft `type=file`
	// Components. Reuses the same path-classifier the untracked
	// enricher uses (PRSD-Task-1 + operator overrides via
	// --rules-file when set), so a path that's "skip" for an
	// untracked walk is also "skip" for a Syft baseline row.
	// Disabled via --no-syft-prefilter for forensic mode.
	prefilterEnricher := syftprefilter.New(nil)
	if !opts.noSyftPrefilter {
		prefilterEnricher = syftprefilter.New(classifier)
	}

	// S3 Task 4: package-registry enrichment. Disabled with
	// `--no-registry`; honors `--no-network` per-source via
	// RequiresNetwork(). Mirror config loaded from YAML if given.
	registryEnricher, err := buildRegistryEnricher(opts, tr, logger)
	if err != nil {
		return nil, err
	}

	// S3 Task 5: lifecycle / EOL enrichment. Disabled with
	// `--no-lifecycle`. Mode online / offline / hybrid via
	// `--lifecycle-mode`; `--no-network` forces offline. Mirrors
	// reuse the same `mirrors:` YAML schema (ecosystem=lifecycle).
	lifecycleEnricher, err := buildLifecycleEnricher(opts, tr, logger)
	if err != nil {
		return nil, err
	}

	return []enrich.Enricher{
		prefilterEnricher,
		attribution.New(),
		basediff.NewWithOptions(basediffOptionsFor(opts, sourceOpts)),
		untrackedEnricher,
		// extractor lifts embedded module / crate / package
		// dependencies out of binary components into top-level
		// components + RelationshipDependsOn edges. Runs after
		// untracked (so untracked-discovered binaries are part of
		// the slate) and before cpe / dedup (so the lifted entries
		// pick up CPEs and feed the dedup key). S3 Task 1 / ADR-0030.
		enrichextractor.New(),
		// registry enricher fills supplier / license / homepage /
		// repository / hashes from npm / PyPI / Maven / Go module
		// proxy. Runs after extractor (so lifted top-level deps get
		// their license/supplier from upstream) and before cpe /
		// dedup. S3 Task 4 / ADR-0033.
		registryEnricher,
		// lifecycle enricher stamps astinus:lifecycle:* properties
		// on OS / runtime Components from endoflife.date. Same
		// pipeline tier as registry — deps on untracked + extractor
		// only (independent of cpe / dedup). S3 Task 5 / ADR-0035.
		lifecycleEnricher,
		cpeEnricher,
		// dedup is the finalize stage — runs LAST so PURLs / CPEs
		// added by upstream enrichers participate in the dedup key.
		// post-Stage-13 hardening Task 2.
		dedup.New(),
		// compliance runs AFTER dedup (PRSD-Task-6 deps =
		// ["dedup"]) so validators see the post-dedup SBOM with
		// every PURL / CPE / Origin already stamped.
		// PRSD-Task-7. S3 Task 2: optionally configured with a
		// per-ecosystem severity override file via
		// `--compliance-config`.
		complianceEnricher,
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
func buildCPEEnricher(opts *enrichOptions, tr http.RoundTripper, logger *slog.Logger, componentCount int) (*cpe.Enricher, error) {
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
	nvdSkipped := false
	if mode != cpesources.ModeOffline {
		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		nvdKey := opts.nvdAPIKey
		if nvdKey == "" {
			nvdKey = os.Getenv("NVD_API_KEY")
		}
		// PRSD post-Task-9 hardening: at large workloads, the
		// anonymous NVD endpoint (5 req/30 s) wedges the cpe phase
		// for hours. Skip the source up-front when the operator is
		// in hybrid mode without an API key. ADR-0028.
		if shouldSkipAnonymousNVDInHybrid(mode, nvdKey, componentCount) {
			nvdSkipped = true
			logger.Warn(telemetry.EventCPENVDSkipped,
				"reason", "hybrid + no NVD_API_KEY + workload above safe threshold",
				"components", componentCount,
				"threshold", nvdHybridSkipThreshold,
				"anonymous_rate", "5 req/30s",
				"estimated_minutes_at_anonymous_rate", estimateAnonymousNVDMinutes(componentCount),
				"advice", nvdSkipAdvice(componentCount),
			)
		} else {
			srcs = append(srcs, cpesources.NewNVDAPI(nvdKey, client))
		}
		srcs = append(srcs, cpesources.NewClearlyDefined(client))
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
		"nvd_authenticated", opts.nvdAPIKey != "" || os.Getenv("NVD_API_KEY") != "",
		"nvd_skipped", nvdSkipped,
		"include_rejected", opts.includeRejectedCPE)
	return cpe.NewWithResolver(resolver).WithIncludeRejected(opts.includeRejectedCPE), nil
}

// buildRegistryEnricher composes the S3-Task-4 registry enricher
// per CLI flags. When --no-registry is set, returns an enricher
// with a nil resolver (no-op Enrich). Otherwise loads the mirror
// YAML, indexes mirrors per ecosystem, instantiates the 4 fully
// implemented sources (npm, pypi, maven, golang) plus the 5 stubs
// (cargo, gem, nuget, deb, alpine) and 2 aggregator stubs
// (repology, ecosyste-ms), wires the (optional) layered cache, and
// returns the enricher. ADR-0033.
func buildRegistryEnricher(opts *enrichOptions, tr http.RoundTripper, logger *slog.Logger) (*registryenrich.Enricher, error) {
	if opts.noRegistry {
		return registryenrich.New(nil).WithLogger(logger), nil
	}
	mirrorsCfg, err := cfgpkg.LoadMirrorsConfig(opts.mirrorsConfig)
	if err != nil {
		return nil, err
	}
	byEco := registryenrich.MirrorsByEcosystem(mirrorsCfg)

	httpClient := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	sources := []registryenrich.Source{
		registrysources.NewNPM(byEco["npm"], httpClient),
		registrysources.NewPyPI(byEco["pypi"], httpClient),
		registrysources.NewMaven(byEco["maven"], httpClient),
		registrysources.NewGolang(byEco["golang"], httpClient),
		registrysources.NewCargo(byEco["cargo"], httpClient),
		registrysources.NewRubyGems(byEco["gem"], httpClient),
		registrysources.NewNuGet(byEco["nuget"], httpClient),
		registrysources.NewDebian(byEco["deb"], httpClient),
		registrysources.NewAlpine(byEco["apk"], httpClient),
		registrysources.NewRepology(byEco["repology"], httpClient),
		registrysources.NewEcosystems(byEco["ecosyste-ms"], httpClient),
	}

	cache, err := buildRegistryCache(opts)
	if err != nil {
		return nil, err
	}

	resolver := registryenrich.NewResolver(registryenrich.ResolverOptions{
		Sources:   sources,
		Cache:     cache,
		NetworkOK: !opts.noNetwork,
		Logger:    logger,
	})
	logger.Info("registry.configured",
		"sources", len(sources),
		"network_ok", !opts.noNetwork,
		"mirrors_total", len(mirrorsCfg.Mirrors),
		"cache_dir", opts.registryCacheDir,
		"cache_ttl", opts.registryCacheTTL.String())
	return registryenrich.New(resolver).WithLogger(logger), nil
}

// buildLifecycleEnricher composes the S3-Task-5 lifecycle enricher.
// `--no-lifecycle` returns a disabled enricher (no-op Enrich).
// Otherwise picks the Source slate per `--lifecycle-mode` +
// `--no-network`, loading the operator-supplied snapshot file when
// `--lifecycle-snapshot` is set (else the embedded seed).
//
// Lifecycle mirrors are read from the same `mirrors:` YAML
// (ecosystem=lifecycle) so corp ops don't manage two configs.
// ADR-0035.
func buildLifecycleEnricher(opts *enrichOptions, tr http.RoundTripper, logger *slog.Logger) (*lifecycle.Enricher, error) {
	if opts.noLifecycle {
		return lifecycle.New(nil).WithLogger(logger), nil
	}
	mode := lifecycle.Mode(strings.ToLower(strings.TrimSpace(opts.lifecycleMode)))
	if !mode.IsKnown() {
		mode = lifecycle.ModeHybrid
	}
	if opts.noNetwork {
		mode = lifecycle.ModeOffline
	}

	bundled, err := loadLifecycleBundled(opts.lifecycleSnapshot)
	if err != nil {
		return nil, err
	}

	mirrorsCfg, err := cfgpkg.LoadMirrorsConfig(opts.mirrorsConfig)
	if err != nil {
		return nil, err
	}
	mirrors := registryenrich.MirrorsByEcosystem(mirrorsCfg)["lifecycle"]
	httpClient := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	online := lifecycle.NewEndOfLife(mirrors, httpClient).WithLogger(logger)

	resolver := lifecycle.NewResolver(lifecycle.ResolverOptions{
		Online:  online,
		Bundled: bundled,
		Mode:    mode,
		Logger:  logger,
	})
	logger.Info("lifecycle.configured",
		"mode", string(mode),
		"snapshot", lifecycleSnapshotLabel(opts.lifecycleSnapshot),
		"bundled_products", bundled.ProductCount(),
		"mirrors", len(mirrors))
	return lifecycle.New(resolver).WithLogger(logger), nil
}

// loadLifecycleBundled returns the BundledSource per the operator's
// `--lifecycle-snapshot` choice. Empty path = embedded seed.
func loadLifecycleBundled(path string) (*lifecycle.BundledSource, error) {
	if path == "" {
		return lifecycle.LoadBundled()
	}
	return lifecycle.LoadBundledFromFile(path)
}

// lifecycleSnapshotLabel renders the snapshot source for the
// `lifecycle.configured` log line.
func lifecycleSnapshotLabel(path string) string {
	if path == "" {
		return "embedded"
	}
	return path
}

// buildRegistryCache returns the cache implementation per CLI
// flags. Empty --registry-cache-dir → MemoryCache only.
func buildRegistryCache(opts *enrichOptions) (registryenrich.Cache, error) {
	mem := registryenrich.NewMemoryCache()
	if opts.registryCacheDir == "" {
		return mem, nil
	}
	disk, err := registryenrich.NewDiskCache(opts.registryCacheDir, opts.registryCacheTTL)
	if err != nil {
		return nil, err
	}
	return registryenrich.NewLayeredCache(mem, disk), nil
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

// configureMetrics returns the *telemetry.Registry the pipeline
// should publish to, or nil when --metrics-output is empty. Also
// binds the registry to the pipeline so per-enricher metrics fire.
//
// PRSD-Task-8.
func configureMetrics(output string, pipeline *enrich.Pipeline) *telemetry.Registry {
	if output == "" {
		return nil
	}
	reg := telemetry.NewRegistry()
	pipeline.WithMetrics(reg)
	return reg
}

// configureTracing wires the pipeline's tracer based on --tracing-endpoint.
// Today every endpoint resolves to NoopTracer (OTel is deferred —
// see ADR-0026); the operator gets a single-line warning so the
// absence of spans is explicit rather than silent.
//
// PRSD-Task-8.
func configureTracing(endpoint string, pipeline *enrich.Pipeline, logger *slog.Logger) {
	tr, deferred := telemetry.InitTracing(endpoint)
	pipeline.WithTracer(tr)
	switch {
	case endpoint == "":
		// Tracing not requested — no log noise.
		return
	case deferred:
		logger.Warn(telemetry.EventTracingDisabled,
			"endpoint", endpoint,
			"reason", "OpenTelemetry exporter not compiled in (see ADR-0026)")
	default:
		logger.Info(telemetry.EventTracingInit, "endpoint", endpoint)
	}
}

// writeMetrics emits the registry's contents to the operator-chosen
// sink. A registry-nil call is a no-op (metrics were never enabled).
//
// Output forms:
//
//	stdout / stderr     → corresponding os.File
//	file:/abs/path      → opened O_CREATE|O_TRUNC|O_WRONLY 0644
//	(other)             → ExitInvalidArgs-like log warning, no file
//
// Errors writing the metrics are logged but do not abort the run —
// the SBOM is the primary artefact; metrics are diagnostic.
func writeMetrics(output string, reg *telemetry.Registry, logger *slog.Logger) {
	if reg == nil {
		return
	}
	w, closer, err := openMetricsSink(output)
	if err != nil {
		logger.Warn("metrics.exported", "error", err.Error())
		return
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	if err := reg.ExportPrometheus(w); err != nil {
		logger.Warn(telemetry.EventMetricsExported, "error", err.Error())
		return
	}
	logger.Info(telemetry.EventMetricsExported,
		"sink", output,
		"metrics", len(reg.Names()))
}

// openMetricsSink resolves the --metrics-output value to an
// io.Writer + an optional Closer the caller must close. Returns an
// error for unrecognised forms; never returns a nil writer alongside
// a nil error.
func openMetricsSink(spec string) (io.Writer, io.Closer, error) {
	switch spec {
	case "stdout":
		return os.Stdout, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	}
	if rest, ok := strings.CutPrefix(spec, "file:"); ok {
		if rest == "" {
			return nil, nil, fmt.Errorf("--metrics-output: empty file path")
		}
		f, err := os.OpenFile(rest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644) //nolint:gosec // operator-chosen path
		if err != nil {
			return nil, nil, fmt.Errorf("--metrics-output: %w", err)
		}
		return f, f, nil
	}
	return nil, nil, fmt.Errorf("--metrics-output %q: want stdout|stderr|file:/path", spec)
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
