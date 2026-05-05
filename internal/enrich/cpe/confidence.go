package cpe

import (
	"fmt"
	"sort"
)

// Threshold defines the confidence cutoffs the orchestrator applies
// when classifying a slate of Candidate proposals into primary,
// alternatives, and rejected entries.
//
// Sprint 3 Task 0: introduces per-Candidate classification so a
// false-positive NVD keyword hit (e.g. yq → Linksys router CPE) is
// quarantined as a `rejected` entry instead of being silently stamped
// as a high-confidence alternative on the Component. See ADR-0029.
type Threshold struct {
	// PrimaryMin is the minimum Confidence a Candidate must score to
	// become the Component's primary `cpe` field. Default 0.70.
	PrimaryMin float64

	// AlternativeMin is the minimum Confidence a Candidate must
	// score to be retained as `astinus:cpe:alternative:N`. Anything
	// below this floor lands in the rejected bucket. Default 0.50.
	AlternativeMin float64
}

// DefaultThreshold returns the Astinus production cutoffs.
func DefaultThreshold() Threshold {
	return Threshold{PrimaryMin: 0.70, AlternativeMin: 0.50}
}

// Classify partitions cands into a primary candidate, kept
// alternatives, and rejected proposals. The slice is sorted by
// confidence descending; ties retain input order.
//
// Rules:
//
//   - The highest-scoring candidate becomes primary iff its
//     Confidence >= t.PrimaryMin.
//   - Every other candidate with Confidence >= t.AlternativeMin
//     becomes an alternative.
//   - Everything else becomes a rejected entry. If the source did not
//     populate RejectedReason already (a hard-reject path such as
//     hardware-CPE-on-software-PURL), Classify fills in a default
//     "below threshold" message.
//
// primary is returned by value through a pointer so callers can
// distinguish "no primary" (nil) from "zero-value primary".
func Classify(cands []Candidate, t Threshold) (primary *Candidate,
	alts []Candidate, rejected []Candidate) {
	if len(cands) == 0 {
		return nil, nil, nil
	}

	sorted := make([]Candidate, len(cands))
	copy(sorted, cands)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Confidence > sorted[j].Confidence
	})

	for i := range sorted {
		c := sorted[i]
		switch {
		case primary == nil && c.Confidence >= t.PrimaryMin:
			cp := c
			primary = &cp
		case c.Confidence >= t.AlternativeMin:
			alts = append(alts, c)
		default:
			if c.RejectedReason == "" {
				c.RejectedReason = fmt.Sprintf(
					"confidence %.2f below threshold %.2f",
					c.Confidence, t.AlternativeMin)
			}
			rejected = append(rejected, c)
		}
	}
	return primary, alts, rejected
}

// DedupeCandidates collapses entries that share the same CPE string.
// The highest-confidence copy wins; on ties the first occurrence is
// kept. Sources are merged into a comma-separated list when distinct
// producers agree on the same CPE — useful provenance for operators.
//
// Called by the enricher before Classify so duplicate proposals from
// (e.g.) bundled + clearly-defined don't artificially inflate the
// alternatives list.
func DedupeCandidates(in []Candidate) []Candidate {
	if len(in) <= 1 {
		return in
	}
	type slot struct {
		idx     int
		sources map[Source]bool
	}
	index := make(map[string]*slot, len(in))
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		s, ok := index[c.CPE]
		if !ok {
			s = &slot{idx: len(out), sources: map[Source]bool{c.Source: true}}
			index[c.CPE] = s
			out = append(out, c)
			continue
		}
		s.sources[c.Source] = true
		if c.Confidence > out[s.idx].Confidence {
			out[s.idx] = c
		}
	}
	for _, s := range index {
		if len(s.sources) > 1 {
			out[s.idx].Source = mergeSources(s.sources)
		}
	}
	return out
}

// mergeSources renders a stable comma-joined list of contributing
// source names so the merged Source field reads "bundled+nvd-api"
// rather than picking one arbitrarily.
func mergeSources(set map[Source]bool) Source {
	names := make([]string, 0, len(set))
	for s := range set {
		names = append(names, string(s))
	}
	sort.Strings(names)
	out := names[0]
	for _, n := range names[1:] {
		out += "+" + n
	}
	return Source(out)
}
