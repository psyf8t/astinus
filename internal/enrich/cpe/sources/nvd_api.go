package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
// Queries `/cpes/2.0?keywordSearch=<name>&resultsPerPage=20`. Each
// returned CPE is scored via scoreNVDMatch — the keyword endpoint is
// substring-matched and routinely yields irrelevant entries (Linksys
// router CPEs for the binary `yq`, German auction sites for any name
// containing `v4`). The scorer assigns each Candidate a per-match
// confidence so the orchestrator can quarantine the noise instead of
// stamping every result as `confidence=high`. ADR-0029.
func (s *NVDAPISource) Match(ctx context.Context, purl cpe.PURL) ([]cpe.Candidate, error) {
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
	return candidatesFromNVDPage(page, purl), nil
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

// candidatesFromNVDPage scores every entry in the NVD page against
// the source PURL. Entries below the orchestrator's hard floor get
// stamped with a RejectedReason so Classify can route them into the
// rejected bucket without losing the diagnostic trail.
//
// Sprint 3 Task 0: replaces the previous matchesFromNVDPage that
// returned every entry stamped `confidence=high` regardless of the
// underlying match strength. ADR-0029.
func candidatesFromNVDPage(page *nvdCPEPage, purl cpe.PURL) []cpe.Candidate {
	out := make([]cpe.Candidate, 0, len(page.Products))
	for _, prod := range page.Products {
		raw := prod.CPE.CPEName
		if raw == "" || !cpe.IsValidCPE(raw) {
			continue
		}
		parsed, err := cpe.Parse(raw)
		if err != nil {
			continue
		}
		// Apply the version sieve only when the PURL pinned one and
		// the parsed CPE pins something other than a wildcard. This
		// keeps NVD-style range entries (`-`, `*`) eligible.
		if purl.Version != "" && !cpeVersionCompatible(parsed.Version, purl.Version) {
			continue
		}
		score, details := scoreNVDMatch(purl, parsed)
		cand := cpe.Candidate{
			CPE:          raw,
			Source:       cpe.Source("nvd-api"),
			Confidence:   score,
			Evidence:     fmt.Sprintf("nvd keyword=%q", purl.Name),
			MatchDetails: details,
		}
		switch {
		case parsed.Part == "h":
			cand.RejectedReason = "hardware-type CPE for software PURL — see ADR-0029"
		case score < 0.30:
			cand.RejectedReason = "weak nvd substring match (vendor/product mismatch)"
		}
		out = append(out, cand)
	}
	return out
}

// scoreNVDMatch assigns a [0, 1] confidence to an NVD CPE entry given
// the PURL it was queried for. Hard rejection (~0.05) for
// hardware-type CPEs on software PURLs — that's the conduit for the
// yq → Linksys-router false positive observed in v0.2 benchmark output.
//
// Otherwise the score is the weighted sum of vendor + product +
// version matches, clamped at 1.0. See ADR-0029 §3 for the table.
//
// Weights (max 1.10 → clamped):
//
//	vendor : 0.50  (exact vendor=namespace OR vendor=name fallback)
//	product: 0.40  (product=name)
//	version: 0.20  (exact)
//
// Vendor=name is the common NVD convention for npm/maven packages
// where the project owns the namespace (e.g. `yq:v4`,
// `expressjs:express`); the fallback gives full vendor weight in
// that case so the entry can still clear PrimaryMin.
func scoreNVDMatch(purl cpe.PURL, parsed cpe.CPEv23) (float64, cpe.MatchDetails) {
	details := cpe.MatchDetails{SearchMethod: "keyword-search"}

	if parsed.Part == "h" {
		details.VendorMatch = "no-match"
		details.ProductMatch = "no-match"
		details.VersionMatch = "n/a"
		return cpe.ConfidenceReject, details
	}

	vendorKind, vendorGain := scoreVendor(parsed.Vendor, purl.Namespace, purl.Name)
	details.VendorMatch = vendorKind

	productKind, productGain := scoreProduct(parsed.Product, purl.Name, purl.Namespace)
	details.ProductMatch = productKind

	versionKind, versionGain := scoreVersion(parsed.Version, purl.Version)
	details.VersionMatch = versionKind

	score := vendorGain + productGain + versionGain
	if score > 1.0 {
		score = 1.0
	}
	return score, details
}

// scoreVendor classifies how the CPE vendor relates to the PURL.
// Two paths reach the full vendor weight:
//
//   - vendor matches PURL namespace exactly (the org-controlled
//     namespace pattern, e.g. maven `org.apache.logging.log4j`).
//   - vendor matches PURL name exactly (the project-owns-namespace
//     pattern: `yq:v4`, `expressjs:express`).
//
// Lower scores reflect substring / fuzzy hits — those are usually
// the cheap NVD keyword false positives.
func scoreVendor(cpeVendor, purlNamespace, purlName string) (string, float64) {
	v := strings.ToLower(cpeVendor)
	if v == "" {
		return "no-match", 0.0
	}
	if k, g := vendorMatchExact(v, strings.ToLower(purlNamespace), strings.ToLower(purlName)); k != "" {
		return k, g
	}
	if k, g := vendorMatchSubstring(v, strings.ToLower(purlNamespace), strings.ToLower(purlName)); k != "" {
		return k, g
	}
	return "no-match", 0.0
}

// vendorMatchExact returns the (kind, gain) pair for an exact or
// normalized vendor match against either the namespace or the name;
// returns ("", 0) when neither side matches at full weight.
func vendorMatchExact(v, ns, nm string) (string, float64) {
	switch {
	case ns != "" && v == ns:
		return "exact", 0.50
	case nm != "" && v == nm:
		return "known-mapping", 0.50
	case ns != "" && normalizeAttr(v) == normalizeAttr(ns):
		return "normalized", 0.40
	case nm != "" && normalizeAttr(v) == normalizeAttr(nm):
		return "normalized", 0.40
	}
	return "", 0.0
}

// vendorMatchSubstring captures the weak substring fallback for
// vendor matches; surfaced separately so scoreVendor stays under
// the gocyclo cap.
func vendorMatchSubstring(v, ns, nm string) (string, float64) {
	if ns != "" && (strings.Contains(v, ns) || strings.Contains(ns, v)) {
		return "substring", 0.10
	}
	if nm != "" && (strings.Contains(v, nm) || strings.Contains(nm, v)) {
		return "substring", 0.10
	}
	return "", 0.0
}

// scoreProduct classifies how the CPE product relates to the PURL.
// Exact name match is the strongest signal; normalized (dash ↔
// underscore) is close behind. A namespace-segment fallback covers
// the unusual pattern where NVD records keep the project name as
// product on a different vendor (rare).
func scoreProduct(cpeProduct, purlName, purlNamespace string) (string, float64) {
	p := strings.ToLower(cpeProduct)
	nm := strings.ToLower(purlName)
	if p == "" || nm == "" {
		return "no-match", 0.0
	}
	switch {
	case p == nm:
		return "exact", 0.40
	case normalizeAttr(p) == normalizeAttr(nm):
		return "normalized", 0.30
	case purlNamespace != "" && p == lastSegment(strings.ToLower(purlNamespace)):
		return "namespace-segment", 0.20
	case strings.Contains(p, nm) || strings.Contains(nm, p):
		return "substring", 0.10
	}
	return "no-match", 0.0
}

// scoreVersion grants partial credit when the PURL pins a version and
// the CPE does too. NVD wildcard entries (`*`, `-`) count as a soft
// match: they cover any version including ours, but don't prove
// anything specific.
func scoreVersion(cpeVersion, purlVersion string) (string, float64) {
	if purlVersion == "" {
		return "wildcard", 0.05
	}
	if cpeVersion == purlVersion {
		return "exact", 0.20
	}
	if cpeVersion == "*" || cpeVersion == "-" || cpeVersion == "" {
		return "wildcard", 0.10
	}
	return "mismatch", 0.0
}

// lastSegment returns the substring after the final '/' or '.' —
// useful when a PURL namespace like `org.apache.logging.log4j`
// should be reduced to its tail (`log4j`) for product comparison.
func lastSegment(s string) string {
	if i := strings.LastIndexAny(s, "/."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// normalizeAttr canonicalises common token variations so that
// dash/underscore differences don't drag a real match down to a
// substring score.
func normalizeAttr(s string) string {
	r := strings.ReplaceAll(s, "-", "_")
	r = strings.ReplaceAll(r, ".", "_")
	return r
}

// cpeVersionCompatible reports whether cpeVersion can plausibly
// describe purlVersion: equality, NVD wildcards, or empty CPE
// version slot all qualify.
func cpeVersionCompatible(cpeVersion, purlVersion string) bool {
	switch cpeVersion {
	case "*", "-", "":
		return true
	}
	return cpeVersion == purlVersion
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
