package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultSWHBaseURL is the public Software Heritage v1 API base URL.
const DefaultSWHBaseURL = "https://archive.softwareheritage.org/api/1"

// SWHMatcher resolves cryptographic digests against the public
// Software Heritage Archive
// (https://docs.softwareheritage.org/devel/swh-web/uri-scheme-api.html).
//
// Lookup form: GET <base>/content/<alg>:<hex>/. Algorithms accepted
// by SWH: sha1, sha256, sha1_git, blake2s256. We translate our
// canonical model.HashAlgorithm* names to SWH's spelling here.
//
// Behaviour:
//
//   - 200 → the response carries `data_url`, file size, and a
//     resolved permalink. We turn the permalink into a Match.Source
//     ("swh:permalink") and extract a `Name` heuristically from
//     `filenames[0]` if present.
//   - 404 → ErrNoMatch.
//   - 429 / 503 → wrapped error so the caller's RateLimitedMatcher
//     can back off (we don't auto-retry inside).
//   - timeout / network → wrapped error (NOT cached).
//
// Wrap with NewCached + NewRateLimited at construction time so the
// upstream API stays happy.
type SWHMatcher struct {
	baseURL string
	client  *http.Client
}

// NewSWHMatcher returns an SWH matcher that talks to baseURL. Pass
// "" to use DefaultSWHBaseURL. The HTTP client SHOULD have a
// reasonable timeout — SWH endpoints can be slow under load.
func NewSWHMatcher(baseURL string, client *http.Client) *SWHMatcher {
	if baseURL == "" {
		baseURL = DefaultSWHBaseURL
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &SWHMatcher{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

// Name implements Matcher.
func (s *SWHMatcher) Name() string { return "swh" }

// Lookup implements Matcher.
func (s *SWHMatcher) Lookup(ctx context.Context, alg, digest string) (Match, error) {
	swhAlg, ok := swhAlgorithm(alg)
	if !ok {
		return Match{}, fmt.Errorf("swh: unsupported algorithm %q: %w", alg, ErrNoMatch)
	}
	url := fmt.Sprintf("%s/content/%s:%s/", s.baseURL, swhAlg, strings.ToLower(digest))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return Match{}, fmt.Errorf("swh: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return Match{}, fmt.Errorf("swh: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return parseSWHResponse(resp.Body)
	case http.StatusNotFound:
		return Match{}, fmt.Errorf("swh: %s: %w", url, ErrNoMatch)
	case http.StatusTooManyRequests:
		return Match{}, fmt.Errorf("swh: rate-limited (HTTP 429) on %s", url)
	default:
		return Match{}, fmt.Errorf("swh: unexpected status %d on %s", resp.StatusCode, url)
	}
}

// swhContentResponse is the subset of SWH's content endpoint we
// care about. Real responses carry many more fields.
type swhContentResponse struct {
	Sha1      string   `json:"sha1"`
	Sha256    string   `json:"sha256"`
	Length    int64    `json:"length"`
	Filenames []string `json:"filenames,omitempty"`
	DataURL   string   `json:"data_url,omitempty"`
	StatusURL string   `json:"status,omitempty"`
}

// maxSWHResponseBytes caps how much of an SWH response body we will
// consume. Real SWH content responses are a few KB; 1 MiB is far
// beyond anything plausible from the upstream API. Defensive cap
// against a hostile / misconfigured intermediary returning a giant
// body. post-stage-13 review F-017.
const maxSWHResponseBytes = 1 << 20

// parseSWHResponse builds a Match from a 200 response body.
func parseSWHResponse(body io.Reader) (Match, error) {
	var r swhContentResponse
	if err := json.NewDecoder(io.LimitReader(body, maxSWHResponseBytes)).Decode(&r); err != nil {
		return Match{}, fmt.Errorf("swh: decode response: %w", err)
	}
	m := Match{Source: "swh"}
	if len(r.Filenames) > 0 {
		m.Name = r.Filenames[0]
	}
	return m, nil
}

// swhAlgorithm maps our canonical algorithm names to the SWH-API
// spelling. SWH accepts a small set; everything else is rejected.
func swhAlgorithm(alg string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "sha1":
		return "sha1", true
	case "sha256":
		return "sha256", true
	default:
		return "", false
	}
}
