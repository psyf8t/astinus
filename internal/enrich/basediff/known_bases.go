package basediff

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// knownBasesBytes is the bundled snapshot of common public-image
// base distros. Refreshed periodically by a future
// `make update-known-bases` toolchain (S4 Task 6 ships only the
// runtime consumer; the refresh script is a Sprint 5 candidate).
//
//go:embed data/known_bases.json
var knownBasesBytes []byte

// KnownBaseEntry is one row in the bundled catalogue. Today the
// entry carries OS-release identity + a small set of sample file
// paths the detector uses for presence checks; future schema
// versions will add per-arch content-hash fingerprints for stronger
// matching (deferred — see ADR-0044 §"Follow-up work"). S4 Task 6.
type KnownBaseEntry struct {
	ID              string   `json:"id"`
	VersionID       string   `json:"version_id"`
	ImageRef        string   `json:"image_ref"`
	SampleFilePaths []string `json:"sample_file_paths"`
}

// KnownBases is the in-memory representation of the bundled
// snapshot. The struct is intentionally small — production
// installations of Astinus carry the snapshot in the binary, so a
// 14-entry catalogue costs ~2 KB in addition to the package data.
type KnownBases struct {
	entries       []KnownBaseEntry
	capturedAt    time.Time
	nextUpdateDue time.Time
}

// LoadBundledKnownBases unmarshals the embedded snapshot. Returns a
// non-nil error only when the bundled JSON fails to parse — that
// would indicate a build-time bug, since the file is //go:embed'ed
// at compile time.
func LoadBundledKnownBases() (*KnownBases, error) {
	return loadKnownBasesFromBytes(knownBasesBytes)
}

// loadKnownBasesFromBytes is the testable variant — exposed via
// unexported name so the test file can drive a fixture JSON without
// exposing a parallel public API. S4 Task 6.
func loadKnownBasesFromBytes(buf []byte) (*KnownBases, error) {
	var doc struct {
		SchemaVersion string           `json:"schema_version"`
		CapturedAt    time.Time        `json:"captured_at"`
		NextUpdateDue time.Time        `json:"next_update_due"`
		Entries       []KnownBaseEntry `json:"entries"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		return nil, fmt.Errorf("basediff: known_bases.json: %w", err)
	}
	if doc.SchemaVersion != "1" {
		return nil, fmt.Errorf("basediff: unsupported known_bases schema %q", doc.SchemaVersion)
	}
	k := &KnownBases{
		entries:       doc.Entries,
		capturedAt:    doc.CapturedAt,
		nextUpdateDue: doc.NextUpdateDue,
	}
	if !doc.NextUpdateDue.IsZero() && time.Now().After(doc.NextUpdateDue) {
		slog.Default().Warn("basediff.known-bases.stale",
			"captured_at", doc.CapturedAt.Format(time.RFC3339),
			"next_update_due", doc.NextUpdateDue.Format(time.RFC3339),
			"hint", "the bundled known-bases snapshot is past its refresh deadline; "+
				"detection still works against entries that don't depend on freshness")
	}
	return k, nil
}

// LookupByOSRelease returns every catalogue entry whose ID matches
// rel.ID (case-insensitive) and whose VersionID matches per
// `versionMatches`. Returns empty slice when nothing matches.
func (k *KnownBases) LookupByOSRelease(rel *OSRelease) []KnownBaseEntry {
	if k == nil || rel == nil || rel.ID == "" {
		return nil
	}
	wantID := strings.ToLower(rel.ID)
	var out []KnownBaseEntry
	for _, e := range k.entries {
		if strings.ToLower(e.ID) == wantID && versionMatches(e.VersionID, rel.VersionID) {
			out = append(out, e)
		}
	}
	return out
}

// Entries returns a defensive copy of the catalogue, primarily for
// tests and diagnostic CLI output.
func (k *KnownBases) Entries() []KnownBaseEntry {
	if k == nil {
		return nil
	}
	out := make([]KnownBaseEntry, len(k.entries))
	copy(out, k.entries)
	return out
}

// UniqueDistroIDs returns the sorted, deduplicated list of distro
// IDs the catalogue carries. Used by the auto-detector when
// building an actionable FallbackReason on a no-known-base outcome —
// operators see the available alternatives. Deterministic order so
// the same diagnostic text reproduces across runs. S6 Task 3 /
// ADR-0060.
func (k *KnownBases) UniqueDistroIDs() []string {
	if k == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(k.entries))
	for _, e := range k.entries {
		id := strings.ToLower(e.ID)
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// VersionsForDistro returns the sorted, deduplicated list of
// known VersionIDs for the given distro ID (case-insensitive).
// Returns an empty slice for an unknown distro. Used by the
// FallbackReason builder to tell operators "we know debian, but
// only versions 11, 12 — not 13". S6 Task 3 / ADR-0060.
func (k *KnownBases) VersionsForDistro(id string) []string {
	if k == nil || id == "" {
		return nil
	}
	wantID := strings.ToLower(id)
	seen := make(map[string]struct{})
	for _, e := range k.entries {
		if strings.ToLower(e.ID) != wantID {
			continue
		}
		if e.VersionID == "" {
			continue
		}
		seen[e.VersionID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// versionMatches reports whether the catalogue's known-version
// string covers the target image's reported VERSION_ID. Exact-match
// is the strong signal; prefix-match (`12` covers `12.5`) handles
// distros that use major-only versions in their catalogue but emit
// fully-qualified versions in os-release.
func versionMatches(known, target string) bool {
	if known == "" || target == "" {
		return known == target
	}
	if known == target {
		return true
	}
	if strings.HasPrefix(target, known+".") {
		return true
	}
	return false
}
