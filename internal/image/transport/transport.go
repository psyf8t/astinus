// Package transport builds the http.RoundTripper that all registry
// traffic flows through.
//
// The transport bundles four concerns the spec calls out
// (sections 8.4 / 9.4 / 10.x):
//
//   - TLS — system CAs by default; optionally augmented with a
//     corporate CA bundle (`Options.CABundle`). mTLS client cert lands
//     in Stage 10 alongside per-registry config.
//   - Proxy — env-driven (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`)
//     by default; explicit `Options.Proxy` URL overrides.
//   - Retry / backoff — wraps the inner transport via
//     hashicorp/go-retryablehttp. Defaults: 3 retries with exponential
//     backoff; honours `Retry-After` headers.
//   - User-Agent — every outgoing request is stamped with
//     "astinus/<version> (+repo URL)" so registries see who's calling.
//
// One transport, one project. Callers do not (and must not) construct
// http.Client themselves — go-containerregistry's `remote.WithTransport`
// accepts whatever we hand back.
package transport

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"

	"github.com/psyf8t/astinus/internal/version"
)

// userAgent is the value sent on every outbound request.
//
// The repo URL is mandatory under the spec's "responsible HTTP client"
// guidance (section 8.4) — it lets a registry operator track us down
// when our traffic is misbehaving.
func userAgent() string {
	return fmt.Sprintf("astinus/%s (+https://github.com/psyf8t/astinus)", version.Version)
}

// Options configures the RoundTripper produced by New.
type Options struct {
	// CABundle is an optional path to a PEM bundle. Certificates are
	// added to the system pool — they do not replace it. Empty string
	// means "use the system pool unchanged".
	CABundle string

	// SkipTLSVerify disables certificate validation. Off by default
	// because the spec section 6.2 marks `--skip-tls-verify` as
	// "не рекомендуется"; surfaced for parity with the CLI flag.
	SkipTLSVerify bool

	// Proxy is the explicit proxy URL. Empty string means "honour
	// HTTP_PROXY / HTTPS_PROXY / NO_PROXY env vars".
	Proxy string

	// Timeout caps a single HTTP request, including retries. Zero
	// means no per-request cap (the cancellation context still
	// applies). Default is 30 s.
	Timeout time.Duration

	// MaxRetries is the number of retry attempts on 5xx / network
	// errors. Default 3. Set to -1 to disable retries entirely.
	MaxRetries int

	// Logger receives debug events about retries. Nil = silent.
	Logger *slog.Logger

	// ClientCert / ClientKey form a PEM-encoded mTLS client
	// certificate. Both must be set or both empty. Per spec
	// section 9.4 (mTLS for high-security environments).
	ClientCert string
	ClientKey  string
}

// defaultTimeout is applied when Options.Timeout is zero.
const defaultTimeout = 30 * time.Second

// defaultRetries is applied when Options.MaxRetries is zero.
const defaultRetries = 3

// New returns an http.RoundTripper configured per opts.
//
// The returned transport is safe for concurrent use and is intended to
// be reused for the lifetime of the process — the caller does NOT need
// to construct it per request.
func New(opts Options) (http.RoundTripper, error) {
	tlsConfig, err := buildTLSConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("transport: tls config: %w", err)
	}

	proxyFunc, err := proxyFunc(opts.Proxy)
	if err != nil {
		return nil, fmt.Errorf("transport: proxy: %w", err)
	}

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tlsConfig
	base.Proxy = proxyFunc

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	retries := opts.MaxRetries
	if retries == 0 {
		retries = defaultRetries
	}
	if retries < 0 {
		retries = 0
	}

	rt := http.RoundTripper(&userAgentTransport{base: base})
	if retries > 0 {
		rc := retryablehttp.NewClient()
		rc.HTTPClient = &http.Client{Transport: rt, Timeout: timeout}
		rc.RetryMax = retries
		rc.RetryWaitMin = 500 * time.Millisecond
		rc.RetryWaitMax = 10 * time.Second
		rc.Logger = newRetryLogger(opts.Logger)
		rt = &retryablehttp.RoundTripper{Client: rc}
	}
	return rt, nil
}

// userAgentTransport stamps the User-Agent header on every outgoing
// request before delegating to base. It also threads the configured
// timeout / cancellation through unchanged.
type userAgentTransport struct {
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (u *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		// Clone so we don't mutate a request the caller still owns.
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", userAgent())
	}
	return u.base.RoundTrip(req)
}

// buildTLSConfig honours opts.CABundle, opts.SkipTLSVerify, and
// opts.ClientCert/Key, and returns a *tls.Config suitable for an
// http.Transport.
func buildTLSConfig(opts Options) (*tls.Config, error) {
	pool, err := loadCAPool(opts.CABundle)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	if opts.SkipTLSVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // explicit opt-in via Options
	}
	clientCert, err := loadClientCertificate(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, err
	}
	if hasClientCert(clientCert) {
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	return cfg, nil
}

// proxyFunc returns the function plugged into http.Transport.Proxy.
// Empty explicit proxy → http.ProxyFromEnvironment (HTTP_PROXY /
// HTTPS_PROXY / NO_PROXY honoured). Otherwise → constant proxy URL.
func proxyFunc(explicit string) (func(*http.Request) (*url.URL, error), error) {
	if explicit == "" {
		return http.ProxyFromEnvironment, nil
	}
	parsed, err := url.Parse(explicit)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", explicit, err)
	}
	return func(*http.Request) (*url.URL, error) { return parsed, nil }, nil
}
