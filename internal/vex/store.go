package vex

import (
	"fmt"
	"os"
	"strings"
)

// Status mirrors the OpenVEX / CycloneDX VEX status vocabulary.
type Status string

// VEX status vocabulary per OpenVEX + CycloneDX VEX. Suppresses()
// is true only for StatusNotAffected and StatusFixed; the other
// two values are operator-visible information that the gate keeps
// for diagnostic surfacing but does NOT use to filter findings.
const (
	StatusAffected           Status = "affected"
	StatusNotAffected        Status = "not_affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Justification mirrors the OpenVEX justification vocabulary.
// `Detail` carries the operator-supplied free-text reason for
// statuses that don't use a structured justification.
type Justification string

// VEX justification vocabulary per OpenVEX 0.2. The CycloneDX VEX
// justification set differs slightly and is normalised at parse
// time via cdxJustificationMap.
const (
	JustComponentNotPresent              Justification = "component_not_present"
	JustVulnerableCodeNotPresent         Justification = "vulnerable_code_not_present"
	JustVulnerableCodeNotInExecutePath   Justification = "vulnerable_code_not_in_execute_path"
	JustVulnerableCodeCannotBeControlled Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustInlineMitigationsAlreadyExist    Justification = "inline_mitigations_already_exist"
)

// Effect is one resolved VEX assertion: "for this vulnID + this
// product PURL, the status is X (with justification Y, sourced from
// VEX file Z)". The Store holds a slice of these; Lookup returns
// the first matching entry.
type Effect struct {
	VulnID        string
	ProductPURL   string
	Status        Status
	Justification Justification
	Detail        string
	Source        string // file path the effect was parsed from
}

// Suppresses reports whether the effect carries a status that the
// compliance gate should suppress (`not_affected` or `fixed`).
// Affected / under_investigation are NOT suppressing — operators
// who VEX-mark something `affected` likely want the gate to keep
// alerting; `under_investigation` is intentionally provisional.
func (e Effect) Suppresses() bool {
	return e.Status == StatusNotAffected || e.Status == StatusFixed
}

// Store is the in-memory collection of VEX effects compiled from
// every input document. Safe for concurrent read after construction;
// not goroutine-safe to mutate (the loader is single-threaded).
type Store struct {
	effects []Effect
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{} }

// Len reports the number of effects in the store.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.effects)
}

// Effects returns a copy of the effect slice — primarily for tests
// and the diagnostic CLI surface.
func (s *Store) Effects() []Effect {
	if s == nil {
		return nil
	}
	out := make([]Effect, len(s.effects))
	copy(out, s.effects)
	return out
}

// Lookup returns the first effect whose VulnID equals vulnID AND
// ProductPURL matches productPURL per `purlsEquivalent`. Returns
// (nil, false) when nothing matches. Order matches the load order
// of input files; multiple effects for the same (vulnID, PURL) are
// possible (e.g. one file marks `fixed`, another `not_affected`) —
// the FIRST match wins. Operators who care about precedence pass
// the higher-priority file first on the CLI.
func (s *Store) Lookup(vulnID, productPURL string) (*Effect, bool) {
	if s == nil || vulnID == "" {
		return nil, false
	}
	for i := range s.effects {
		if s.effects[i].VulnID != vulnID {
			continue
		}
		if purlsEquivalent(s.effects[i].ProductPURL, productPURL) {
			return &s.effects[i], true
		}
	}
	return nil, false
}

// Sources returns the deduplicated, ordered list of file paths the
// effects in the store were parsed from. Used by the
// `astinus:vex:sources` SBOM metadata stamp.
func (s *Store) Sources() []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(s.effects))
	for _, e := range s.effects {
		if e.Source == "" || seen[e.Source] {
			continue
		}
		seen[e.Source] = true
		out = append(out, e.Source)
	}
	return out
}

// AddEffect appends an effect; used by the parsers. Empty PURLs
// AND empty VulnIDs are dropped — a VEX statement that can't
// be resolved against any component is noise.
func (s *Store) AddEffect(e Effect) {
	if s == nil {
		return
	}
	if e.VulnID == "" || e.ProductPURL == "" {
		return
	}
	s.effects = append(s.effects, e)
}

// LoadStore reads every path in `files`, detects each file's
// format, parses, and merges effects into a single Store. Returns
// the (possibly empty) store plus a non-nil error if ANY file
// fails to read or parse — operators who VEX-decorate a build
// should hear about a typo in the file path or a malformed JSON
// document instead of silently getting an empty store.
func LoadStore(files []string) (*Store, error) {
	store := NewStore()
	for _, path := range files {
		body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
		if err != nil {
			return store, fmt.Errorf("vex: read %s: %w", path, err)
		}
		format := DetectFormat(body)
		switch format {
		case FormatOpenVEX:
			if err := parseOpenVEXInto(store, body, path); err != nil {
				return store, fmt.Errorf("vex: parse OpenVEX %s: %w", path, err)
			}
		case FormatCDXVEX:
			if err := parseCDXVEXInto(store, body, path); err != nil {
				return store, fmt.Errorf("vex: parse CDX-VEX %s: %w", path, err)
			}
		default:
			return store, fmt.Errorf("vex: %s: unrecognised VEX format (expected OpenVEX or CycloneDX VEX)", path)
		}
	}
	return store, nil
}

// purlsEquivalent reports whether two PURLs name the same product
// for VEX suppression purposes. Two cases match:
//
//  1. Exact string equality.
//  2. Same base (stripped @version) AND either side carries `@*`
//     (operator-asserted "any version" / wildcard).
//
// More sophisticated version-range matching (`@>=1.2,<2.0`) is
// future work — today the contract is "version-pin or wildcard".
// S6 Task 6 / ADR-0063.
func purlsEquivalent(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	aBase, aVer := splitPURL(a)
	bBase, bVer := splitPURL(b)
	if aBase != bBase {
		return false
	}
	if aVer == "*" || bVer == "*" {
		return true
	}
	return false
}

// splitPURL splits a PURL string at the first `@` into (base, version).
// Both parts may be empty.
func splitPURL(p string) (base, version string) {
	if i := strings.Index(p, "@"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}
