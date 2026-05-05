package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// endOfLifeUpstream is the public endoflife.date API base. Surfaced
// as a const so tests can swap with httptest.Server via WithUpstream.
const endOfLifeUpstream = "https://endoflife.date/api"

// EndOfLifeSource fetches `<base>/<product>.json` and matches the
// requested cycle key. Honours the same MirrorChain semantics as
// the registry enricher (S3 Task 4): replace-mode mirrors exclude
// upstream, fallback-mode mirrors fall through to upstream on 404.
//
// Operators with air-gapped environments mirror endoflife.date on
// internal Artifactory and configure a `mirrors:` entry with
// `ecosystem: lifecycle`.
type EndOfLifeSource struct {
	mirrors  []config.MirrorEntry
	client   *http.Client
	logger   *slog.Logger
	upstream string
}

// NewEndOfLife returns a Source backed by mirrors + client. nil
// client → registry.DefaultClient (env-proxy honoured).
func NewEndOfLife(mirrors []config.MirrorEntry, client *http.Client) *EndOfLifeSource {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &EndOfLifeSource{
		mirrors:  mirrors,
		client:   client,
		logger:   slog.Default(),
		upstream: endOfLifeUpstream,
	}
}

// WithUpstream overrides the endoflife.date base URL. Test-only.
func (s *EndOfLifeSource) WithUpstream(u string) *EndOfLifeSource {
	s.upstream = u
	return s
}

// WithLogger overrides the slog destination.
func (s *EndOfLifeSource) WithLogger(l *slog.Logger) *EndOfLifeSource {
	if l != nil {
		s.logger = l
	}
	return s
}

// Name implements Source.
func (*EndOfLifeSource) Name() string { return "endoflife.date" }

// RequiresNetwork implements Source.
func (*EndOfLifeSource) RequiresNetwork() bool { return true }

// Fetch implements Source. Returns ErrNotFound when the product is
// missing or the cycle key doesn't match any entry. Wraps the
// registry sentinel errors (`registry.ErrNotFound` /
// `registry.ErrTransient`) into the lifecycle vocabulary so the
// Resolver branches on the right values.
func (s *EndOfLifeSource) Fetch(ctx context.Context, product, version string) (*Lifecycle, error) {
	if product == "" || version == "" {
		return nil, ErrNotFound
	}
	chain := registry.MirrorChain{
		Mirrors:  s.mirrors,
		Upstream: s.upstream,
	}
	pathSuffix := "/" + product + ".json"

	var raw []eolCycle
	parser := func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&raw)
	}
	if err := registry.FetchJSON(ctx, s.client, chain, pathSuffix, s.Name(), parser, s.logger); err != nil {
		switch {
		case errors.Is(err, registry.ErrNotFound):
			return nil, ErrNotFound
		case errors.Is(err, registry.ErrTransient):
			return nil, ErrTransient
		default:
			return nil, err
		}
	}
	for i := range raw {
		if cycleMatches(raw[i].Cycle, version) {
			return convertCycle(&raw[i]), nil
		}
	}
	return nil, ErrNotFound
}

// eolCycle is the on-the-wire schema. `support` and `eol` are
// `json.RawMessage` because endoflife.date uses both date strings
// (`"2026-04-30"`) and booleans (`true` / `false`) for these
// fields. We translate to time.Time + bool fields downstream.
//
// `lts` is also polymorphic at the source (sometimes a date when
// LTS support extends past the cycle's normal EOL, sometimes a
// bool); we only project the boolean meaning today.
type eolCycle struct {
	Cycle       string          `json:"cycle"`
	ReleaseDate string          `json:"releaseDate"`
	Support     json.RawMessage `json:"support"`
	EOL         json.RawMessage `json:"eol"`
	Latest      string          `json:"latest"`
	LTS         json.RawMessage `json:"lts"`
}

// convertCycle projects an on-wire cycle to the canonical Lifecycle
// shape, normalising the polymorphic date-or-bool fields.
func convertCycle(c *eolCycle) *Lifecycle {
	out := &Lifecycle{
		Cycle:  c.Cycle,
		Latest: c.Latest,
	}
	out.ReleaseDate = parseDate(c.ReleaseDate)
	out.ActiveSupportEnd, out.SupportBoolean = parseDateOrBool(c.Support)
	out.EOL, out.EOLBoolean = parseDateOrBool(c.EOL)
	out.LTS = parseLTS(c.LTS)
	return out
}

// parseDateOrBool handles endoflife.date's polymorphic "support"
// and "eol" fields:
//
//   - `"2026-04-30"` → (time.Time, "")
//   - `true`         → (zero, "true")
//   - `false`        → (zero, "false")
//   - `null` / empty → (zero, "")
func parseDateOrBool(raw json.RawMessage) (time.Time, string) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return time.Time{}, ""
	}
	if trimmed == "true" {
		return time.Time{}, "true"
	}
	if trimmed == "false" {
		return time.Time{}, "false"
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, ""
	}
	return parseDate(s), ""
}

// parseLTS reads endoflife.date's `lts` field which is sometimes
// a boolean and sometimes a date (the cycle becomes LTS at that
// date). We treat any truthy / date value as LTS=true.
func parseLTS(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "true" {
		return true
	}
	if trimmed == "false" || trimmed == "" || trimmed == "null" {
		return false
	}
	// Any non-empty string means LTS-with-date-trigger; treat as LTS.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return true
	}
	return false
}

// parseDate decodes an ISO-8601 date string ("2026-04-30") into a
// time.Time at midnight UTC. Returns the zero value on parse
// failure so callers can branch on `IsZero()`.
func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// cycleMatches reports whether the requested version matches the
// cycle key. endoflife.date cycle keys are short forms ("20" for
// Node 20.x, "3.11" for Python 3.11.x); the requested version is
// already truncated by the product mapping's VersionFormat, so a
// direct equality check is the common case.
//
// Tolerant of leading zeros and `v` prefixes that some Components
// carry.
func cycleMatches(cycle, version string) bool {
	if cycle == version {
		return true
	}
	stripped := strings.TrimPrefix(version, "v")
	return cycle == stripped
}

// FetchProduct returns every cycle endoflife.date publishes for
// the given product as raw eolCycle entries. Used by
// `astinus lifecycle update` to materialise the snapshot file —
// the subcommand walks the known products and writes the combined
// JSON per the BundledSource layout. Surfaced separately from
// Fetch so the subcommand doesn't have to reverse-engineer the
// per-cycle parser.
func (s *EndOfLifeSource) FetchProduct(ctx context.Context, product string) ([]Lifecycle, error) {
	if product == "" {
		return nil, ErrNotFound
	}
	chain := registry.MirrorChain{Mirrors: s.mirrors, Upstream: s.upstream}
	var raw []eolCycle
	parser := func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&raw)
	}
	if err := registry.FetchJSON(ctx, s.client, chain, "/"+product+".json", s.Name(), parser, s.logger); err != nil {
		switch {
		case errors.Is(err, registry.ErrNotFound):
			return nil, ErrNotFound
		case errors.Is(err, registry.ErrTransient):
			return nil, ErrTransient
		default:
			return nil, fmt.Errorf("lifecycle: fetch product %q: %w", product, err)
		}
	}
	out := make([]Lifecycle, len(raw))
	for i := range raw {
		out[i] = *convertCycle(&raw[i])
	}
	return out, nil
}
