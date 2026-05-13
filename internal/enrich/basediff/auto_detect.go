package basediff

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// AutoDetectionResult is the outcome of `AutoDetector.Detect`.
// Returned even on "no detection" — `BaseImageRef == ""` plus a
// non-empty `FallbackReason` carries that signal. Errors are
// reserved for unrecoverable I/O failures. S4 Task 6.
type AutoDetectionResult struct {
	// BaseImageRef is the detected base ("alpine:3.20",
	// "debian:12-slim", …). Empty when detection didn't reach a
	// confident answer.
	BaseImageRef string

	// Confidence ∈ [0, 1]. Label-based detection scores 1.0;
	// content-based detection scores per `scoreOne`.
	Confidence float64

	// Method records how the result was reached: "label",
	// "os-release+known-bases", or "" when detection produced no
	// answer.
	Method string

	// FallbackReason is operator-visible text explaining a
	// no-detection outcome ("no /etc/os-release in image", "no
	// known base for alpine 99.0", …). Empty on a successful
	// detection.
	FallbackReason string

	// OSReleaseID + OSReleaseVersionID are the parsed identity
	// signals we operated on (when available). Surfaced so the
	// caller can stamp them onto SBOM metadata for downstream
	// audit. S4 Task 6.
	OSReleaseID        string
	OSReleaseVersionID string

	// MatchedSamples records the count of `sample_file_paths` from
	// the chosen catalogue entry that the target image actually
	// carries. Useful for tests and audit; informational at
	// runtime.
	MatchedSamples int
	TotalSamples   int
}

// AutoDetector runs the content-based base-image detection pipeline.
//
// Steps (S4 Task 6):
//
//  1. Try label-based detection (cheap, definitive).
//  2. Read /etc/os-release (or alpine-release / usr/lib/os-release).
//  3. Look up candidate base entries in the bundled known-bases
//     catalogue, keyed on os-release `ID` + `VERSION_ID`.
//  4. Score each candidate via `scoreOne` (presence of sample-file
//     paths).
//  5. Pick the highest-confidence candidate above MinConfidence;
//     otherwise return a "no detection" result with a human-readable
//     FallbackReason.
type AutoDetector struct {
	known         *KnownBases
	MinConfidence float64
}

// NewAutoDetector returns a detector backed by the bundled
// known-bases catalogue. MinConfidence defaults to 0.70 when the
// caller passes 0; values outside [0, 1] are clamped.
func NewAutoDetector(known *KnownBases, minConfidence float64) *AutoDetector {
	if minConfidence <= 0 {
		minConfidence = 0.70
	}
	if minConfidence > 1 {
		minConfidence = 1
	}
	return &AutoDetector{known: known, MinConfidence: minConfidence}
}

// Detect runs the pipeline against img. Returns a non-nil result
// in every successful run; errors are reserved for unrecoverable
// I/O failures (image layers can't be enumerated, etc.). When
// detection produces no confident answer the result's
// `BaseImageRef` is empty and `FallbackReason` is populated.
func (d *AutoDetector) Detect(ctx context.Context, img v1.Image) (*AutoDetectionResult, error) {
	if img == nil {
		return nil, fmt.Errorf("basediff: auto-detect needs a non-nil image")
	}

	// Step 1: label-based. Reuses the existing detectFromLabels
	// helper (`detector.go`).
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("basediff: read image config: %w", err)
	}
	if ref := detectFromLabels(cfg); ref != "" {
		return &AutoDetectionResult{
			BaseImageRef: ref,
			Confidence:   1.0,
			Method:       "label",
		}, nil
	}

	// Step 2: read os-release.
	rel, err := readOSReleaseFromImage(ctx, img)
	if errors.Is(err, errNoOSRelease) {
		return &AutoDetectionResult{
			FallbackReason: "no /etc/os-release in image (scratch-based or custom)",
		}, nil
	}
	if err != nil {
		return &AutoDetectionResult{
			FallbackReason: fmt.Sprintf("read os-release: %v", err),
		}, nil
	}
	if rel == nil || rel.ID == "" {
		return &AutoDetectionResult{
			FallbackReason: "no parseable os-release content (empty / malformed)",
		}, nil
	}

	// Step 3: catalogue lookup.
	candidates := d.known.LookupByOSRelease(rel)
	if len(candidates) == 0 {
		return &AutoDetectionResult{
			OSReleaseID:        rel.ID,
			OSReleaseVersionID: rel.VersionID,
			FallbackReason: fmt.Sprintf("no known base for %s %s",
				rel.ID, rel.VersionID),
		}, nil
	}

	// Step 4 + 5: score, pick best, gate on MinConfidence.
	best, score, matched, total := d.scoreBest(ctx, img, candidates)
	if best == nil || score < d.MinConfidence {
		return &AutoDetectionResult{
			OSReleaseID:        rel.ID,
			OSReleaseVersionID: rel.VersionID,
			FallbackReason: fmt.Sprintf("best candidate confidence %.2f below threshold %.2f",
				score, d.MinConfidence),
			MatchedSamples: matched,
			TotalSamples:   total,
		}, nil
	}
	return &AutoDetectionResult{
		BaseImageRef:       best.ImageRef,
		Confidence:         score,
		Method:             "os-release+known-bases",
		OSReleaseID:        rel.ID,
		OSReleaseVersionID: rel.VersionID,
		MatchedSamples:     matched,
		TotalSamples:       total,
	}, nil
}

// scoreBest iterates the candidate slice, scores each via scoreOne,
// and returns the highest-scoring entry plus its score + sample-
// match counts. When the candidate list is empty returns (nil, 0, 0, 0).
func (d *AutoDetector) scoreBest(ctx context.Context, img v1.Image, candidates []KnownBaseEntry) (*KnownBaseEntry, float64, int, int) {
	var (
		best  *KnownBaseEntry
		score float64
		bm    int
		bt    int
	)
	for i := range candidates {
		s, matched, total := d.scoreOne(ctx, img, candidates[i])
		if best == nil || s > score {
			best = &candidates[i]
			score = s
			bm = matched
			bt = total
		}
	}
	return best, score, bm, bt
}

// scoreOne assigns a confidence ∈ [0, 1] to a single candidate.
//
// Signals (S4 Task 6 ships only the first two; per-arch sample-file
// content hashes are deferred):
//
//   - 0.50 base score for an OS-release ID+VERSION match. The
//     LookupByOSRelease step already verified this, so every
//     candidate we see here clears it.
//   - up to 0.30 from sample-file presence (linear in the
//     match fraction).
//   - 0.20 reserved for the deferred content-hash signal.
//
// The total caps at 0.80 today (0.50 + 0.30). The MinConfidence
// default of 0.70 is calibrated to require both os-release + at
// least 2/3 of the sample files to be present.
func (d *AutoDetector) scoreOne(ctx context.Context, img v1.Image, cand KnownBaseEntry) (float64, int, int) {
	score := 0.50
	matched, total := 0, len(cand.SampleFilePaths)
	if total == 0 {
		return score, matched, total
	}
	for _, p := range cand.SampleFilePaths {
		if fileExistsInImage(ctx, img, p) {
			matched++
		}
	}
	presence := float64(matched) / float64(total)
	score += 0.30 * presence
	if score > 1 {
		score = 1
	}
	return score, matched, total
}

// fileExistsInImage probes the image for path's presence without
// loading the body. Uses readFileFromImage's short-circuit walk —
// we accept the cost of an extra walk per candidate today; the
// total number of candidates is small (typically 1-3 for a given
// os-release ID + version match), and the implementation reuses
// the layer.WalkFiles fast path.
//
// S4 Task 6 follow-up: a `(*FileMap).Has(path)` direct accessor
// would let us probe in O(1) after a single Walk; deferred.
func fileExistsInImage(ctx context.Context, img v1.Image, path string) bool {
	_, _, err := readFileFromImage(ctx, img, path)
	return err == nil
}
