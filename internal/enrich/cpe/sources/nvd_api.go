package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// NVDAPIBaseURL is the public NVD CPE API host. Surfaced as a const
// so tests can swap with httptest.Server.
const NVDAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

// NVD documented rate limits (https://nvd.nist.gov/developers/start-here):
//
//   - Without API key: 5 requests per 30-second window.
//   - With API key:   50 requests per 30-second window.
//
// We translate to a steady requests-per-second rate so our token
// bucket doesn't burst into a 429 at the start of every window.
const (
	nvdAnonymousRPS     = 5.0 / 30.0  // ~0.167 rps
	nvdAuthenticatedRPS = 50.0 / 30.0 // ~1.67 rps
)

// NVDAPISource queries the public NVD CPE API. Authenticated callers
// (operators with an apiKey) get 10× the throughput.
//
// Errors from individual requests are returned to the orchestrator;
// the orchestrator drops the Source's contribution but continues with
// the next Source. A streak of NVD failures (e.g. an outage) does
// NOT abort the cpe enricher.
type NVDAPISource struct {
	apiKey     string
	httpClient *http.Client
	limiter    *tokenBucket
	baseURL    string
}

// NewNVDAPI constructs a NVDAPISource. apiKey is optional — pass ""
// for anonymous access (subject to the lower rate limit).
//
// When client is nil, a default client with a 30 s timeout is used.
func NewNVDAPI(apiKey string, client *http.Client) *NVDAPISource {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	rps := nvdAnonymousRPS
	if apiKey != "" {
		rps = nvdAuthenticatedRPS
	}
	return &NVDAPISource{
		apiKey:     apiKey,
		httpClient: client,
		limiter:    newTokenBucket(rps, 1),
		baseURL:    NVDAPIBaseURL,
	}
}

// WithBaseURL overrides the API host. Test-only.
func (s *NVDAPISource) WithBaseURL(u string) *NVDAPISource {
	s.baseURL = u
	return s
}

// Name implements Source.
func (*NVDAPISource) Name() string { return "nvd-api" }

// Match implements Source.
//
// Queries `/cpes/2.0?keywordSearch=<name>&resultsPerPage=20`. Returns
// every CPE from the response that includes the PURL's version (or
// every CPE if the PURL has no version). The version filter cuts down
// the response size on common names like "log4j" that have hundreds
// of historical entries.
func (s *NVDAPISource) Match(ctx context.Context, purl cpe.PURL) ([]cpe.Match, error) {
	if purl.Name == "" {
		return nil, nil
	}
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("nvd-api: rate limit wait: %w", err)
	}
	page, err := s.fetchPage(ctx, purl.Name)
	if err != nil {
		return nil, err
	}
	return matchesFromNVDPage(page, purl.Version), nil
}

// fetchPage performs the HTTP GET against the NVD CPE API and parses
// the response into nvdCPEPage. Extracted from Match so the latter
// stays under the cyclomatic-complexity cap.
func (s *NVDAPISource) fetchPage(ctx context.Context, name string) (*nvdCPEPage, error) {
	q := url.Values{}
	q.Set("keywordSearch", name)
	q.Set("resultsPerPage", "20")
	endpoint := s.baseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd-api: build request: %w", err)
	}
	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd-api: GET %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("nvd-api: rate-limited (%d) — consider setting NVD_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd-api: %d from %s", resp.StatusCode, endpoint)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, nvdAPIMaxBody))
	if err != nil {
		return nil, fmt.Errorf("nvd-api: read body: %w", err)
	}
	var page nvdCPEPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("nvd-api: parse JSON: %w", err)
	}
	return &page, nil
}

// matchesFromNVDPage filters page's products by version (when version
// is non-empty) and rewraps the survivors as cpe.Match values.
func matchesFromNVDPage(page *nvdCPEPage, version string) []cpe.Match {
	out := make([]cpe.Match, 0, len(page.Products))
	for _, prod := range page.Products {
		c := prod.CPE.CPEName
		if c == "" || !cpe.IsValidCPE(c) {
			continue
		}
		if version != "" && !cpeNameMatchesVersion(c, version) {
			continue
		}
		out = append(out, cpe.Match{
			CPE:        c,
			Source:     cpe.Source("nvd-api"),
			Confidence: cpe.ConfidenceHigh,
		})
	}
	return out
}

// RequiresNetwork implements Source.
func (*NVDAPISource) RequiresNetwork() bool { return true }

// Priority implements Source — NVD is the canonical authority for
// CPEs; ranks above ClearlyDefined among online sources.
func (*NVDAPISource) Priority() int { return 80 }

// nvdAPIMaxBody caps the response body. NVD API pages can carry
// hundreds of products; 4 MiB is plenty for a 20-result page.
const nvdAPIMaxBody = 4 << 20

// nvdCPEPage is the subset of the NVD CPE API response we read.
// Schema: https://nvd.nist.gov/developers/products
type nvdCPEPage struct {
	Products []struct {
		CPE struct {
			CPEName string `json:"cpeName"`
		} `json:"cpe"`
	} `json:"products"`
}

// cpeNameMatchesVersion reports whether the version segment of cpeName
// is a wildcard, the literal version, or a prefix-style match. This
// is intentionally lenient — NVD often records ranges in the version
// field (`-`, `*`) and the orchestrator wants to keep those entries
// rather than drop them.
func cpeNameMatchesVersion(cpeName, version string) bool {
	parsed, err := cpe.Parse(cpeName)
	if err != nil {
		return true // be lenient on parse failure; downstream filters can drop
	}
	if parsed.Version == "*" || parsed.Version == "-" || parsed.Version == "" {
		return true
	}
	return parsed.Version == version
}

// ─── tokenBucket ─────────────────────────────────────────────────────

// tokenBucket is a tiny in-tree implementation of a token-bucket
// rate limiter. Production code in fingerprint/matcher uses a
// similar pattern (Stage-13 RateLimitedMatcher); we don't share the
// implementation because the matcher's bucket couples to its
// Match interface and the API surface here is different.
//
// The bucket refills at `rps` tokens per second up to a maximum of
// `burst` tokens. Wait blocks until a token is available or ctx is
// cancelled.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	burst      float64
	rps        float64
	lastRefill time.Time
}

func newTokenBucket(rps float64, burst int) *tokenBucket {
	if rps <= 0 {
		rps = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{
		tokens:     float64(burst),
		burst:      float64(burst),
		rps:        rps,
		lastRefill: time.Now(),
	}
}

// Wait blocks until at least one token is available, or returns
// ctx.Err() if the context is cancelled first.
func (b *tokenBucket) Wait(ctx context.Context) error {
	for {
		wait := b.tryAcquire()
		if wait <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// loop and try again
		}
	}
}

// tryAcquire returns 0 when a token was taken, or the duration the
// caller should wait before trying again.
func (b *tokenBucket) tryAcquire() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.rps
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastRefill = now
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	missing := 1 - b.tokens
	return time.Duration(missing/b.rps*float64(time.Second)) + time.Millisecond
}
