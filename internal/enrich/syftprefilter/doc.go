// Package syftprefilter is the pre-pipeline cleanup stage that
// drops or marks Syft-supplied `type=file` Components which match
// the bundled path-classifier rules.
//
// # Why a pre-filter
//
// Syft's `file-cataloger` indexes every visible file in an image
// and emits each one as a `type=file` Component. On the v0.2
// reference image (~1 GB multi-stage Node) this produced 3992
// type=file rows for paths like:
//
//   - `/etc/apt/apt.conf.d/01autoremove`
//   - `/etc/cron.d/e2scrub_all`
//   - `/etc/pam.d/login`
//   - `/etc/logrotate.d/...`
//
// None of those files have a version, PURL, or CPE; they aren't
// scannable for vulnerabilities; they don't help compliance; they
// inflate SBOM size by ~3-4× and slow downstream tools.
//
// The Stage-4 untracked enricher already has a path classifier
// (PRSD-Task-1) with rules covering exactly these paths, but it
// only fires on files Astinus discovers — not on the Syft
// baseline. This enricher closes the gap by applying the same
// classifier to the input SBOM Components before the pipeline runs.
//
// # Pipeline placement
//
// Dependencies() returns nil so the topological sorter (with stable
// input-order tie-breaking) places this enricher first when it
// appears first in the CLI's allEnrichers() slice. Running first
// means downstream enrichers (attribution, basediff, untracked,
// extractor, cpe, dedup, compliance) all see the cleaned-up
// component set.
//
// # Behavior
//
// Per Component (only `Type == ComponentTypeFile`):
//
//   - ActionSkip / ActionRedundantUnderArchive → drop entirely;
//     remove orphaned edges from sbom.Relationships.
//   - ActionMarkAsNoise / ActionMarkAsRedundant → keep but stamp
//     `astinus:noise = true` + `astinus:noise:rule = <rule>` so
//     downstream consumers can filter without losing the data.
//   - No rule matched → keep unchanged.
//
// Operators can disable the entire stage via `--no-syft-prefilter`
// for forensic mode where every file matters. ADR-0032.
package syftprefilter
