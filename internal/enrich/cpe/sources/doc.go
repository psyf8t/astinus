// Package sources is a pluggable backend layer for the cpe enricher.
//
// # Why this exists
//
// The Hardening-Sprint #1 cpe enricher uses a fixed two-step
// resolver: bundled JSON mapping → heuristic name=name fallback.
// That covers ~36 % of PURL'd components on the reference image.
// Production deployments need:
//
//   - Online sources (NVD API, ClearlyDefined) that resolve PURLs the
//     bundled mapping does not know about.
//   - Offline sources (the bundled mapping plus an operator-supplied
//     dictionary on disk).
//   - Hybrid mode that prefers offline (cheap, deterministic) and
//     falls through to online (slow, network-bound) only when the
//     offline sources miss.
//
// # Architecture
//
// Each Source is one backend (PatternMatcher, LocalDictionary,
// ClearlyDefined, NVDAPI). The package's Resolver:
//
//  1. Sorts sources by Priority (high first).
//  2. Filters by Mode — online sources are dropped in offline mode.
//  3. Walks each source in order; returns the first non-empty result
//     when its first match is high-confidence, otherwise accumulates.
//  4. Caches the (PURL → []Match) result so a second component with
//     the same PURL doesn't pay the cost twice.
//
// # What this package does NOT do
//
// It does not invoke the cpe enricher; it does not stamp Component
// properties. The cpe enricher's existing `Enricher` consumes a
// `cpe.Resolver` interface; the orchestrator here implements that
// interface so the integration is opaque from the enricher's POV.
package sources
