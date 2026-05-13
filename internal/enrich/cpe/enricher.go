package cpe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable cpe`).
const Name = "cpe"

// Default wall-time bounds for the CPE enricher. Operators tune via
// the `--cpe-total-timeout` / `--cpe-source-timeout` /
// `--cpe-call-timeout` CLI flags. S6 Task 0 / ADR-0057.
const (
	DefaultTotalCap         = 3 * time.Minute
	DefaultSourceTimeout    = 60 * time.Second
	DefaultCallTimeout      = 10 * time.Second
	DefaultProgressEveryN   = 100
	DefaultProgressInterval = 10 * time.Second
)

// ErrSourceUnavailable is returned from Enrich when the resolver is
// in --cpe-mode hybrid and a per-call timeout or total cap fires.
// The CLI maps it to exit 60 (ExitCPESourceUnavailable). Mirrors the
// orchestrator-layer sentinel in `internal/enrich/cpe/sources`.
// S6 Task 0 / ADR-0057.
var ErrSourceUnavailable = errors.New("cpe source unavailable")

// Enricher is the cpe enrich.Enricher implementation.
//
// Sprint 3 Task 0 changed the output schema:
//
//   - The Component's `cpe` field carries the single highest-confidence
//     candidate (>= Threshold.PrimaryMin).
//   - Other candidates that score >= Threshold.AlternativeMin are
//     surfaced as `astinus:cpe:alternative:N` properties, with their
//     own `:source` and `:confidence` siblings.
//   - Candidates below the alternative floor (and any hard-rejected
//     hardware-CPE-on-software-PURL entries from NVD) are dropped from
//     the SBOM by default. With `--include-rejected-cpe` they appear
//     as `astinus:cpe:rejected:N` for diagnostics.
//
// The previous schema stamped a single `astinus:cpe:confidence=high`
// onto the Component regardless of the underlying candidates, which
// surfaced router/auction-site CPEs to vulnerability scanners as
// authoritative — see ADR-0029.
type Enricher struct {
	chain           Resolver
	threshold       Threshold
	includeRejected bool
	policies        map[string]*EcosystemPolicy
	strict          bool // ModeHybrid / ModeOnline — propagate ErrSourceUnavailable

	totalCap         time.Duration
	progressEveryN   int
	progressInterval time.Duration
}

// New returns an Enricher with DefaultChain() and DefaultThreshold().
func New() *Enricher {
	return &Enricher{
		chain:            DefaultChain(),
		threshold:        DefaultThreshold(),
		policies:         DefaultPolicies(),
		totalCap:         DefaultTotalCap,
		progressEveryN:   DefaultProgressEveryN,
		progressInterval: DefaultProgressInterval,
	}
}

// NewWithResolver returns an Enricher with the supplied resolver.
// Useful for tests that want to drive a deterministic chain.
func NewWithResolver(r Resolver) *Enricher {
	return &Enricher{
		chain:            r,
		threshold:        DefaultThreshold(),
		policies:         DefaultPolicies(),
		totalCap:         DefaultTotalCap,
		progressEveryN:   DefaultProgressEveryN,
		progressInterval: DefaultProgressInterval,
	}
}

// WithTotalCap sets the wall-time cap on Enrich. Zero disables the
// cap (legacy / tests). The CLI passes --cpe-total-timeout (default
// 3 minutes). S6 Task 0 / ADR-0057.
func (e *Enricher) WithTotalCap(d time.Duration) *Enricher {
	e.totalCap = d
	return e
}

// WithProgressTuning overrides the progress-log cadence. Every N
// components OR after `interval` of wall-clock, whichever comes
// first, the enricher emits `cpe.enricher.progress` so operators can
// see the walk isn't wedged. Pass zero for either to keep the
// default; pass negative to disable. S6 Task 0.
func (e *Enricher) WithProgressTuning(everyN int, interval time.Duration) *Enricher {
	if everyN != 0 {
		e.progressEveryN = everyN
	}
	if interval != 0 {
		e.progressInterval = interval
	}
	return e
}

// WithStrictMode toggles whether per-call timeouts surface as
// ErrSourceUnavailable (exit 60 in the CLI) instead of being
// silently absorbed. Set to true for --cpe-mode hybrid; false for
// --cpe-mode auto / offline. ADR-0051 + ADR-0057.
func (e *Enricher) WithStrictMode(b bool) *Enricher {
	e.strict = b
	return e
}

// WithIncludeRejected toggles whether rejected candidates are written
// to the SBOM as `astinus:cpe:rejected:N` properties (in addition to
// the always-on debug log). Used by `--include-rejected-cpe`.
func (e *Enricher) WithIncludeRejected(b bool) *Enricher {
	e.includeRejected = b
	return e
}

// WithThreshold overrides the confidence cutoffs the enricher applies
// when classifying candidates. Useful for policy-driven tuning.
func (e *Enricher) WithThreshold(t Threshold) *Enricher {
	e.threshold = t
	return e
}

// WithPolicies overrides the per-ecosystem CPE policy table. Used by
// tests and (eventually) by a `--cpe-policy` CLI surface to project
// operator overrides on top of `DefaultPolicies()`. Pass nil to
// restore the defaults. S4 Task 3.
func (e *Enricher) WithPolicies(p map[string]*EcosystemPolicy) *Enricher {
	if p == nil {
		e.policies = DefaultPolicies()
	} else {
		e.policies = p
	}
	return e
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. PRSD-Task-6: cpe needs
// PURLs on every Component the SBOM carries — the multi-modal
// extractors (PRSD-Task-4, wired into untracked.processFile) are
// the source of those PURLs for binary-shaped untracked entries.
// Declaring "untracked" guarantees we only resolve once the PURLs
// are populated. S3 Task 1 adds "extractor" so the lifted
// embedded-dependency components (yq's gopkg.in/yaml.v3 etc.) also
// pick up CPEs.
func (*Enricher) Dependencies() []string { return []string{"untracked", "extractor"} }

// Enrich implements enrich.Enricher.
//
// bundle is required for signature compatibility with the pipeline
// but the cpe enricher does not consume the image — its inputs are
// purely the SBOM components.
//
// S6 Task 0: the enricher's wall-time is now bounded by `e.totalCap`
// (default 3 min). When the cap fires in --cpe-mode auto, Enrich
// stamps `astinus:cpe:total-cap-hit=true` plus the components-
// processed count on `sbom.Metadata` and returns nil — the pipeline
// continues with whatever CPEs were resolved. When the cap fires in
// strict mode (--cpe-mode hybrid), Enrich returns ErrSourceUnavailable
// so the CLI can exit 60 per ADR-0051. ADR-0057.
//
//nolint:contextcheck // defensive nil-check at the entry point; pipeline always passes a non-nil ctx
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("cpe: nil sbom")
	}
	_ = bundle // unused; kept for the Enricher signature

	if ctx == nil {
		ctx = context.Background()
	}
	if e.totalCap > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.totalCap)
		defer cancel()
	}

	start := time.Now()
	stats := enrichStats{}
	total := countComponentsRecursive(sbom.Components)

	capHit, strictErr := e.walkWithDeadline(ctx, sbom.Components, total, start, &stats)
	elapsed := time.Since(start)

	stampEnrichMetadata(sbom, capHit, elapsed, stats.examined, e.resolverStatuses())

	slog.Default().Info("cpe.complete",
		"components_examined", stats.examined,
		"components_total", total,
		"had_cpe_already", stats.hadCPEAlready,
		"added_cpe", stats.addedCPE,
		"validated", stats.validated,
		"no_match", stats.noMatch,
		"no_purl", stats.noPURL,
		"purl_error", stats.purlError,
		"alternatives_kept", stats.alternativesKept,
		"rejected", stats.rejectedCount,
		"total_cap_hit", capHit,
		"elapsed", elapsed,
	)
	if strictErr != nil {
		return strictErr
	}
	return nil
}

// walkWithDeadline runs enrichOne over every component, but checks
// ctx.Done() at the head of each iteration so a fired total-cap
// triggers an orderly exit (vs a hard kill of the in-flight HTTP
// call). Returns (capHit, strictErr): when ctx.Err() != nil before
// completion, capHit is true; when the enricher is in strict mode,
// the function also returns ErrSourceUnavailable so the CLI can
// exit 60. S6 Task 0.
func (e *Enricher) walkWithDeadline(
	ctx context.Context,
	comps []model.Component,
	total int,
	start time.Time,
	stats *enrichStats,
) (bool, error) {
	logger := slog.Default()
	lastProgress := start
	strictHit := false

	w := componentWalker{
		ctx:          ctx,
		total:        total,
		start:        start,
		lastProgress: &lastProgress,
		logger:       logger,
		stats:        stats,
		enrich:       e,
		strictHit:    &strictHit,
	}
	capHit := w.run(comps)
	if strictHit && e.strict {
		return capHit, ErrSourceUnavailable
	}
	if capHit && e.strict {
		// Total-cap fired before any per-call timeout did, but the
		// operator asked for strict semantics — still exit 60.
		return capHit, ErrSourceUnavailable
	}
	return capHit, nil
}

// componentWalker carries the per-walk state through walkComponents.
// Field bag rather than method args because the walker recurses into
// SubComponents and the linter doesn't like 8-arg helpers.
type componentWalker struct {
	ctx          context.Context
	total        int
	start        time.Time
	lastProgress *time.Time
	logger       *slog.Logger
	stats        *enrichStats
	enrich       *Enricher
	strictHit    *bool
}

// run iterates `comps` (recursing into SubComponents) and returns
// true when ctx.Done() fired before completion. Each iteration
// checks for cancellation and emits a progress log when N components
// or the progress-interval has elapsed since the last one.
func (w *componentWalker) run(comps []model.Component) bool {
	for i := range comps {
		select {
		case <-w.ctx.Done():
			w.logger.Warn("cpe.enricher.total-cap-hit",
				"elapsed", time.Since(w.start),
				"components_processed", w.stats.examined,
				"components_remaining", w.total-w.stats.examined,
				"hint", "increase --cpe-total-timeout or use --cpe-mode offline")
			return true
		default:
		}
		w.maybeLogProgress()
		w.enrichOneCtx(&comps[i])
		if *w.strictHit {
			return false
		}
		if len(comps[i].SubComponents) > 0 {
			if hit := w.run(comps[i].SubComponents); hit {
				return true
			}
			if *w.strictHit {
				return false
			}
		}
	}
	return false
}

// enrichOneCtx is the ctx-aware sibling of Enricher.enrichOne — it
// uses ResolveCtx when the resolver supports it so per-call deadlines
// propagate, and surfaces strict-mode ErrSourceUnavailable through
// the walker's strictHit flag (the walker stops on the next
// iteration). S6 Task 0.
func (w *componentWalker) enrichOneCtx(c *model.Component) {
	w.stats.examined++
	clearCPEProperties(c)
	hadExisting := len(c.CPEs) > 0
	if hadExisting {
		w.stats.hadCPEAlready++
	}
	cands := candidatesFromExistingCPEs(c.CPEs)
	if hadExisting {
		w.stats.validated++
	}
	purl, purlErr := ParsePURL(c.PURL)
	policy := policyForEcosystem(w.enrich.policies, purl.Type)
	if c.PURL == "" {
		if !hadExisting {
			w.stats.noPURL++
			return
		}
		w.enrich.writeResults(c, cands, w.stats, policy)
		return
	}
	if purlErr != nil {
		w.stats.purlError++
		setProp(c, "astinus:cpe:purl-error", purlErr.Error())
		return
	}
	resolved, err := w.enrich.resolve(w.ctx, purl)
	if errors.Is(err, ErrSourceUnavailable) {
		*w.strictHit = true
		return
	}
	cands = append(cands, resolved...)
	if len(cands) == 0 {
		w.stats.noMatch++
		setProp(c, "astinus:cpe:lookup", "no-match")
		return
	}
	if w.enrich.writeResults(c, cands, w.stats, policy) {
		w.stats.addedCPE++
	}
}

// maybeLogProgress emits cpe.enricher.progress if N components have
// been processed since the last log or progress-interval has elapsed,
// whichever comes first.
func (w *componentWalker) maybeLogProgress() {
	if w.enrich.progressEveryN <= 0 && w.enrich.progressInterval <= 0 {
		return
	}
	now := time.Now()
	shouldLogByCount := w.enrich.progressEveryN > 0 &&
		w.stats.examined > 0 &&
		w.stats.examined%w.enrich.progressEveryN == 0
	shouldLogByTime := w.enrich.progressInterval > 0 &&
		now.Sub(*w.lastProgress) >= w.enrich.progressInterval
	if !shouldLogByCount && !shouldLogByTime {
		return
	}
	percent := 0.0
	if w.total > 0 {
		percent = float64(w.stats.examined) / float64(w.total) * 100
	}
	w.logger.Info("cpe.enricher.progress",
		"processed", w.stats.examined,
		"total", w.total,
		"percent", percent,
		"elapsed", time.Since(w.start))
	*w.lastProgress = now
}

// resolve dispatches to ResolveCtx when the underlying resolver
// supports it (S6 Task 0 — ctx-aware path); otherwise falls back to
// the context-less Resolve. The ctx-less path is taken by older
// chains (BundledResolver, HeuristicResolver, Chain) that don't make
// outbound calls and don't need cancellation.
//
//nolint:contextcheck // defensive nil-check; the walker always passes the bounded ctx
func (e *Enricher) resolve(ctx context.Context, purl PURL) ([]Candidate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cr, ok := e.chain.(ContextResolver); ok {
		return cr.ResolveCtx(ctx, purl)
	}
	return e.chain.Resolve(purl), nil
}

// resolverStatuses surfaces per-source completion statuses from the
// underlying resolver when it tracks them (MultiSourceResolver
// does). Returns an empty map when the resolver type doesn't, so
// the caller can range over the result unconditionally.
func (e *Enricher) resolverStatuses() map[string]string {
	type statusReporter interface {
		SourceStatuses() map[string]string
	}
	if sr, ok := e.chain.(statusReporter); ok {
		return sr.SourceStatuses()
	}
	return map[string]string{}
}

// countComponentsRecursive returns the total number of components
// in the SBOM, including SubComponents. Used for progress-log
// percentages and the components-remaining warn-log field. Cheap
// (single pass; no allocations).
func countComponentsRecursive(comps []model.Component) int {
	n := 0
	for i := range comps {
		n++
		if len(comps[i].SubComponents) > 0 {
			n += countComponentsRecursive(comps[i].SubComponents)
		}
	}
	return n
}

// stampEnrichMetadata writes the S6-T0 wall-time observability
// stamps onto sbom.Metadata.Properties. Idempotent — overwriting on
// re-enrich is intentional (latest run wins). Per-source statuses
// are added under the `astinus:cpe:source-status:<name>` family.
func stampEnrichMetadata(sbom *model.SBOM, capHit bool, elapsed time.Duration, processed int, statuses map[string]string) {
	if sbom == nil {
		return
	}
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	if capHit {
		sbom.Metadata.Properties[model.PropertyCPETotalCapHit] = "true"
	} else {
		sbom.Metadata.Properties[model.PropertyCPETotalCapHit] = "false"
	}
	sbom.Metadata.Properties[model.PropertyCPEElapsedSeconds] = fmt.Sprintf("%.2f", elapsed.Seconds())
	sbom.Metadata.Properties[model.PropertyCPEComponentsProcessed] = fmt.Sprintf("%d", processed)

	// Drop any stale per-source-status entries from a previous run
	// before writing the new set.
	for k := range sbom.Metadata.Properties {
		if strings.HasPrefix(k, model.PropertyCPESourceStatusPrefix) {
			delete(sbom.Metadata.Properties, k)
		}
	}
	for name, status := range statuses {
		sbom.Metadata.Properties[model.PropertyCPESourceStatusPrefix+name] = status
	}
}

// enrichStats counts what the enricher did across one Enrich call.
// Surfaced via the cpe.complete log so operators can see actual
// enrichment effectiveness (post-Stage-13 hardening Task 5.3).
type enrichStats struct {
	examined         int
	hadCPEAlready    int
	addedCPE         int // components for which the resolver added at least one CPE
	validated        int // existing CPEs validated (and the component had any)
	noMatch          int // no candidate cleared even the alternative floor
	noPURL           int // no PURL at all → can't enrich
	purlError        int // PURL malformed
	alternativesKept int // count of `astinus:cpe:alternative:N` properties written
	rejectedCount    int // count of candidates classified as rejected
}

// candidatesFromExistingCPEs converts CPE strings already on a
// Component into Candidate proposals. Valid entries score
// ConfidenceMedium so they remain primary in the absence of a better
// resolver match; invalid entries score ConfidenceReject so Classify
// surfaces them with an explanatory RejectedReason.
func candidatesFromExistingCPEs(cpes []string) []Candidate {
	if len(cpes) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(cpes))
	for _, s := range cpes {
		if IsValidCPE(s) {
			out = append(out, Candidate{
				CPE:        s,
				Source:     SourceInput,
				Confidence: ConfidenceMedium,
				Evidence:   "input SBOM",
				MatchDetails: MatchDetails{
					SearchMethod: "purl-direct",
				},
			})
			continue
		}
		out = append(out, Candidate{
			CPE:            s,
			Source:         SourceInput,
			Confidence:     ConfidenceReject,
			Evidence:       "input SBOM",
			RejectedReason: "input CPE failed CPE 2.3 syntax validation",
		})
	}
	return out
}

// writeResults runs Classify over cands and projects the result onto
// the Component. Returns true when the Component picked up at least
// one CPE that wasn't already present.
//
// S4 Task 3 wires the per-ecosystem policy:
//  1. NormalizeVersion rewrites every candidate's CPE version slot
//     (Go modules drop the leading `v` to match NVD's `X.Y.Z` shape).
//  2. RejectVendors drops candidates whose vendor segment matches a
//     module-path TLD NVD never registers (`go.uber.org`, `k8s.io`,
//     …). The rejected entries surface in the debug log so operators
//     can audit, but they never reach classification.
//  3. EvidenceOnly demotes the chosen primary from Component.CPEs to
//     `astinus:cpe:evidence`, stamps `astinus:cpe:scope =
//     evidence-only` plus a human-readable `astinus:cpe:rationale`.
//     The scanner-facing CPE list stays empty (or unchanged from the
//     input) so CPE-keyed vulnerability matching doesn't fire on
//     coordinates the registry doesn't actually carry.
func (e *Enricher) writeResults(c *model.Component, cands []Candidate, stats *enrichStats, policy *EcosystemPolicy) bool {
	if policy == nil {
		policy = policyForEcosystem(e.policies, "")
	}

	cands = applyPolicyToCandidates(c, cands, policy)
	cands = DedupeCandidates(cands)
	primary, alts, rejected := Classify(cands, e.threshold)

	originalCPEs := append([]string(nil), c.CPEs...)
	c.CPEs = nil

	added := writePrimary(c, primary, originalCPEs, policy)

	for i, alt := range alts {
		idx := i + 1
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d", idx), alt.CPE)
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d:source", idx), string(alt.Source))
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d:confidence", idx), formatConfidence(alt.Confidence))
		stats.alternativesKept++
	}

	for i, rej := range rejected {
		slog.Default().Debug("cpe.rejected",
			"component", c.Name,
			"cpe", rej.CPE,
			"confidence", rej.Confidence,
			"source", rej.Source,
			"reason", rej.RejectedReason)
		stats.rejectedCount++
		if !e.includeRejected {
			continue
		}
		idx := i + 1
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d", idx), rej.CPE)
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:source", idx), string(rej.Source))
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:confidence", idx), formatConfidence(rej.Confidence))
		if rej.RejectedReason != "" {
			setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:reason", idx), rej.RejectedReason)
		}
	}

	return added
}

// setValidationStamps mirrors the legacy validated/invalid stamps so
// downstream consumers (compliance, sarif, summary) keep working.
// Looks at the ORIGINAL set of CPEs that the component arrived with,
// not the post-classification slate.
func setValidationStamps(c *model.Component, original []string) {
	if len(original) == 0 {
		return
	}
	good, bad := 0, 0
	for _, s := range original {
		if IsValidCPE(s) {
			good++
		} else {
			bad++
		}
	}
	switch {
	case bad == 0:
		setProp(c, "astinus:cpe:validated", "true")
	case good == 0:
		setProp(c, "astinus:cpe:validated", "false")
		setProp(c, "astinus:cpe:invalid", "true")
	default:
		setProp(c, "astinus:cpe:validated", "partial")
	}
}

// clearCPEProperties drops every astinus:cpe:* breadcrumb from c so
// the enricher can rewrite a fresh slate. Kept tight on the cpe:
// prefix so we don't accidentally clobber other astinus:* keys.
func clearCPEProperties(c *model.Component) {
	if c.Properties == nil {
		return
	}
	for k := range c.Properties {
		if strings.HasPrefix(k, "astinus:cpe:") {
			delete(c.Properties, k)
		}
	}
}

// formatConfidence renders a confidence float as a 2-decimal string
// for property values. Renderers that gate on it (sarif, summary)
// parse it back to compare against their own thresholds.
func formatConfidence(c float64) string {
	return fmt.Sprintf("%.2f", c)
}

// contains is a tiny helper used to dedupe primary CPEs against the
// component's prior set.
func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// setProp inserts (key, value) into c.Properties, creating the map
// when needed.
func setProp(c *model.Component, key, value string) {
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties[key] = value
}

// applyPolicyToCandidates runs the ecosystem policy's pre-classify
// passes: version normalisation (NormalizeVersion) and vendor
// rejection (RejectVendors). Returns the filtered slice; the
// original is untouched. S4 Task 3.
func applyPolicyToCandidates(c *model.Component, cands []Candidate, policy *EcosystemPolicy) []Candidate {
	if policy.NormalizeVersion != nil {
		for i := range cands {
			cands[i].CPE = applyVersionNormalization(cands[i].CPE, policy.NormalizeVersion)
		}
	}
	if len(policy.RejectVendors) > 0 {
		cands = filterRejectedVendors(c, cands, policy.RejectVendors)
	}
	return cands
}

// writePrimary projects the chosen primary candidate onto the
// Component according to the ecosystem policy. Returns true when the
// row picked up a primary CPE the input didn't already carry.
// Extracted from writeResults to keep cognitive complexity under
// the linter budget. S4 Task 3.
//
// S5 Task 0: a narrow per-PURL exception (`KeepPrimaryPurls`)
// overrides EvidenceOnly for components whose PURL coordinate is
// known to be registered in NVD's CPE dictionary even though the
// surrounding ecosystem policy demotes everything else (Go
// stdlib's `cpe:2.3:a:golang:go:*` is the motivating case —
// ADR-0047).
func writePrimary(c *model.Component, primary *Candidate, originalCPEs []string, policy *EcosystemPolicy) bool {
	keepPrimary := primary != nil &&
		!policy.EmitPrimary &&
		matchesKeepPrimary(c.PURL, policy.KeepPrimaryPurls)

	switch {
	case primary != nil && (policy.EmitPrimary || keepPrimary):
		c.CPEs = []string{primary.CPE}
		setProp(c, "astinus:cpe:source", string(primary.Source))
		setProp(c, "astinus:cpe:confidence", formatConfidence(primary.Confidence))
		if primary.Evidence != "" {
			setProp(c, "astinus:cpe:evidence", primary.Evidence)
		}
		if keepPrimary {
			// The component would have been demoted to evidence-only
			// by the ecosystem policy but matched a KeepPrimary entry.
			// Stamp the exception for audit traceability.
			setProp(c, "astinus:cpe:exception-applied", "keep-primary")
			if policy.KeepPrimaryRationale != "" {
				setProp(c, "astinus:cpe:exception-rationale", policy.KeepPrimaryRationale)
			}
		}
		setValidationStamps(c, originalCPEs)
		return !contains(originalCPEs, primary.CPE)

	case primary != nil:
		// Evidence-only path: never expose to Component.CPEs (scanner-
		// facing). Preserve the candidate so auditors and operator
		// tooling can see what the resolver picked.
		c.CPEs = nil
		setProp(c, "astinus:cpe:evidence", primary.CPE)
		setProp(c, "astinus:cpe:source", string(primary.Source))
		setProp(c, "astinus:cpe:confidence", formatConfidence(primary.Confidence))
		setProp(c, "astinus:cpe:scope", "evidence-only")
		if policy.Rationale != "" {
			setProp(c, "astinus:cpe:rationale", policy.Rationale)
		}
		setValidationStamps(c, originalCPEs)
		return false

	case len(originalCPEs) > 0:
		// Nothing cleared the primary floor but we shouldn't drop the
		// input CPEs silently — keep them so downstream consumers still
		// see the data the operator started with.
		c.CPEs = originalCPEs
		setValidationStamps(c, originalCPEs)
		setProp(c, "astinus:cpe:lookup", "no-primary-above-threshold")
		return false

	default:
		setProp(c, "astinus:cpe:lookup", "no-match")
		return false
	}
}

// filterRejectedVendors drops Candidates whose CPE vendor segment
// matches one of the policy's RejectVendors entries. Surfaced via a
// per-component debug log so operators can audit. S4 Task 3.
func filterRejectedVendors(c *model.Component, cands []Candidate, reject []string) []Candidate {
	if len(cands) == 0 || len(reject) == 0 {
		return cands
	}
	out := make([]Candidate, 0, len(cands))
	for _, cand := range cands {
		vendor := cpeVendor(cand.CPE)
		if vendor != "" && matchesAnyVendor(vendor, reject) {
			slog.Default().Debug("cpe.rejected.by-policy",
				"component", c.Name,
				"cpe", cand.CPE,
				"vendor", vendor)
			continue
		}
		out = append(out, cand)
	}
	return out
}
