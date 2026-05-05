package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// ClearlyDefinedBaseURL is the public ClearlyDefined API host.
// Surfaced as a const so tests can swap with httptest.Server.
const ClearlyDefinedBaseURL = "https://api.clearlydefined.io"

// ClearlyDefinedSource queries https://clearlydefined.io for the
// `identifiers.cpe` array on a definition. ClearlyDefined coordinates
// follow the shape `<type>/<provider>/<namespace>/<name>/<revision>`
// — we map PURL types onto these.
type ClearlyDefinedSource struct {
	httpClient *http.Client
	baseURL    string
}

// NewClearlyDefined returns a ClearlyDefinedSource using client for
// HTTP. When client is nil, http.DefaultClient with a 10 s timeout
// is substituted.
func NewClearlyDefined(client *http.Client) *ClearlyDefinedSource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ClearlyDefinedSource{
		httpClient: client,
		baseURL:    ClearlyDefinedBaseURL,
	}
}

// WithBaseURL overrides the API host. Test-only — never used in
// production.
func (s *ClearlyDefinedSource) WithBaseURL(u string) *ClearlyDefinedSource {
	s.baseURL = u
	return s
}

// Name implements Source.
func (*ClearlyDefinedSource) Name() string { return "clearly-defined" }

// Match implements Source.
//
// Translates the PURL into ClearlyDefined coordinates, fetches the
// definition, and returns every CPE listed under
// `identifiers.cpe`. Returns nil + nil when the PURL cannot be
// translated, when ClearlyDefined returns 404, or when the
// definition has no CPE identifiers.
//
// Errors are returned only for HTTP 5xx and parser failures —
// "not found" is not an error.
func (s *ClearlyDefinedSource) Match(ctx context.Context, purl cpe.PURL) ([]cpe.Candidate, error) {
	coords, ok := purlToCDCoordinates(purl)
	if !ok {
		return nil, nil
	}
	endpoint := s.baseURL + "/definitions/" + url.PathEscape(coords)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("clearly-defined: build request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clearly-defined: GET %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("clearly-defined: %d from %s", resp.StatusCode, endpoint)
	case resp.StatusCode != http.StatusOK:
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, clearlyDefinedMaxBody))
	if err != nil {
		return nil, fmt.Errorf("clearly-defined: read body: %w", err)
	}
	var def cdDefinition
	if err := json.Unmarshal(body, &def); err != nil {
		return nil, fmt.Errorf("clearly-defined: parse JSON: %w", err)
	}

	out := make([]cpe.Candidate, 0, len(def.Described.Identifiers.CPE))
	for _, c := range def.Described.Identifiers.CPE {
		if !cpe.IsValidCPE(c) {
			continue
		}
		out = append(out, cpe.Candidate{
			CPE:        c,
			Source:     cpe.Source("clearly-defined"),
			Confidence: cpe.ConfidenceHigh,
			Evidence:   "clearly-defined identifiers.cpe",
			MatchDetails: cpe.MatchDetails{
				SearchMethod: "purl-direct",
			},
		})
	}
	return out, nil
}

// RequiresNetwork implements Source.
func (*ClearlyDefinedSource) RequiresNetwork() bool { return true }

// Priority implements Source — ClearlyDefined sits below NVD because
// its identifiers.cpe field is curated by humans + tools and is
// occasionally stale. Still authoritative when present.
func (*ClearlyDefinedSource) Priority() int { return 70 }

// clearlyDefinedMaxBody caps the response body at a defensive 1 MiB.
// Real definitions are < 50 KiB; the cap defends against a
// pathological response.
const clearlyDefinedMaxBody = 1 << 20

// cdDefinition is the subset of the ClearlyDefined definition shape
// we read. The full schema is much larger; we only need
// `described.identifiers.cpe`.
type cdDefinition struct {
	Described struct {
		Identifiers struct {
			CPE []string `json:"cpe"`
		} `json:"identifiers"`
	} `json:"described"`
}

// purlToCDCoordinates returns the ClearlyDefined coordinate string
// for a parsed PURL, or ok=false when the PURL type is not
// recognised by ClearlyDefined.
//
// Coordinates: `<type>/<provider>/<namespace>/<name>/<revision>`.
// `-` is the documented placeholder for an empty namespace.
func purlToCDCoordinates(p cpe.PURL) (string, bool) {
	if p.Name == "" {
		return "", false
	}
	revision := p.Version
	if revision == "" {
		// CD requires a revision component; an empty version means
		// we can't form a deterministic coordinate. Skip.
		return "", false
	}
	switch p.Type {
	case "npm":
		ns := "-"
		if p.Namespace != "" {
			ns = p.Namespace
		}
		return "npm/npmjs/" + ns + "/" + p.Name + "/" + revision, true
	case "pypi":
		return "pypi/pypi/-/" + p.Name + "/" + revision, true
	case "maven":
		if p.Namespace == "" {
			return "", false
		}
		return "maven/mavencentral/" + p.Namespace + "/" + p.Name + "/" + revision, true
	case "nuget":
		return "nuget/nuget/-/" + p.Name + "/" + revision, true
	case "gem":
		return "gem/rubygems/-/" + p.Name + "/" + revision, true
	case "cargo":
		return "crate/cratesio/-/" + p.Name + "/" + revision, true
	case "golang":
		// CD supports git/<provider>/<namespace>/<name>/<sha>;
		// PURL versions for golang are usually `v1.2.3` (a tag,
		// not a sha), which CD does not always have. Best effort
		// — we still try; CD returns 404 when it has no record.
		if p.Namespace == "" {
			return "", false
		}
		return "git/github/" + p.Namespace + "/" + p.Name + "/" + revision, true
	default:
		return "", false
	}
}
