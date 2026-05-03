package telemetry

// Event vocabulary for slog `msg` values used across Astinus.
//
// # Why constants
//
// Per the PRSD-Task-8 design, every slog event Astinus emits should
// use a name from this file rather than an inline string literal.
// Centralising the vocabulary lets log-aggregation operators write
// dashboards / alerts against stable values; renames here propagate
// through the codebase via the compiler instead of being a
// search-and-replace.
//
// Naming convention
//
//	<subsystem>.<action>[.<state>]
//
// e.g. `enricher.done`, `cpe.source.error`. The dot-separated
// hierarchy lets log-aggregation tooling do prefix-grouped queries
// (`subsystem:enricher.*`).
//
// # Adoption
//
// The existing call sites still use inline string literals (the
// PRSD-Task-8 introduction is non-breaking). New call sites SHOULD
// use the constant; old call sites can be migrated incrementally.
// The `TestEventsAllConstantsUnique` test guarantees no two
// constants share a value, so collisions can't sneak in via copy-
// paste. The `TestEventsStringFormat` test guarantees every value
// follows the dot-separated convention.
const (
	// ─── Pipeline events ────────────────────────────────────────────

	EventPipelineStart = "pipeline.start"
	EventPipelineDone  = "pipeline.done"
	EventPipelineOrder = "pipeline.order"
	EventEnricherStart = "enricher.start"
	EventEnricherDone  = "enricher.done"
	EventEnricherFail  = "enricher.fail"
	EventEnricherError = "enricher.error"

	// ─── SBOM events ────────────────────────────────────────────────

	EventSBOMLoaded    = "sbom.loaded"
	EventSBOMSaved     = "sbom.saved"
	EventSBOMValidated = "sbom.validated"

	// ─── Image / source events ──────────────────────────────────────

	EventImageOpened           = "image.opened"
	EventImageClosed           = "image.closed"
	EventLayerProcessed        = "layer.processed"
	EventRuntimeDetected       = "runtime.detected"
	EventSourceSelected        = "source.selected"
	EventSourceAutodetectProbe = "source.autodetect.daemon.probe"

	// ─── Per-enricher events ────────────────────────────────────────

	EventBasediffDiff      = "basediff.diff"
	EventBasediffContent   = "basediff.content"
	EventBasediffFallback  = "basediff.fallback"
	EventBasediffPartial   = "basediff.partial"
	EventClusterDetected   = "untracked.cluster.detected"
	EventClusterFailed     = "untracked.cluster.detect-failed"
	EventUntrackedStats    = "untracked.stats"
	EventUntrackedRules    = "untracked.rules.loaded"
	EventCPEResolverConfig = "cpe.resolver.configured"
	EventCPEComplete       = "cpe.complete"
	EventCPESourceError    = "cpe.source.error"
	EventCPELocalLoaded    = "cpe.local.loaded"
	EventCPELocalSkip      = "cpe.local.skip"
	EventDedupComplete     = "dedup.complete"

	// ─── Compliance events (PRSD-Task-7) ────────────────────────────

	EventComplianceComplete       = "compliance.complete"
	EventComplianceValidatorError = "compliance.validator.error"
	EventComplianceGatePassed     = "compliance.gate.passed"
	EventComplianceGateFailed     = "compliance.gate.failed"

	// ─── Telemetry / observability events (PRSD-Task-8) ─────────────

	EventMetricsExported = "metrics.exported"
	EventTracingDisabled = "tracing.disabled"
	EventTracingInit     = "tracing.init"
)

// AllEvents is the slice of every constant defined above. The
// uniqueness + format tests iterate it; metric label dictionaries
// can also auto-populate from it.
//
// Keep this slice in sync with the const block above. Adding a new
// constant requires appending it here (the test will fail if you
// forget).
var AllEvents = []string{
	EventPipelineStart, EventPipelineDone, EventPipelineOrder,
	EventEnricherStart, EventEnricherDone, EventEnricherFail, EventEnricherError,
	EventSBOMLoaded, EventSBOMSaved, EventSBOMValidated,
	EventImageOpened, EventImageClosed, EventLayerProcessed,
	EventRuntimeDetected, EventSourceSelected, EventSourceAutodetectProbe,
	EventBasediffDiff, EventBasediffContent, EventBasediffFallback, EventBasediffPartial,
	EventClusterDetected, EventClusterFailed, EventUntrackedStats, EventUntrackedRules,
	EventCPEResolverConfig, EventCPEComplete, EventCPESourceError,
	EventCPELocalLoaded, EventCPELocalSkip, EventDedupComplete,
	EventComplianceComplete, EventComplianceValidatorError,
	EventComplianceGatePassed, EventComplianceGateFailed,
	EventMetricsExported, EventTracingDisabled, EventTracingInit,
}
