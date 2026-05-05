//go:build acceptance

package helpers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// FakeProxy is a minimal HTTP proxy that records every request it
// proxies to upstream. Tests assert on RequestCount + AuthHeader
// to verify that Astinus's outbound calls actually flowed through
// the proxy when the operator configured HTTP_PROXY / HTTPS_PROXY.
//
// HTTPS CONNECT is unsupported — the test stays on plain HTTP via
// `httptest.Server` URLs. Real corporate proxies all support
// CONNECT; the in-process fake accepts plain GET so the test
// doesn't need a TLS termination dance.
type FakeProxy struct {
	server   *httptest.Server
	upstream *httptest.Server
	requests int64
	mu       sync.Mutex
	lastAuth string
}

// NewFakeProxy starts a proxy that forwards every request to
// upstream. Caller defers Close().
func NewFakeProxy(tb testing.TB, upstream *httptest.Server) *FakeProxy {
	tb.Helper()
	fp := &FakeProxy{upstream: upstream}
	fp.server = httptest.NewServer(http.HandlerFunc(fp.handle))
	tb.Cleanup(fp.Close)
	return fp
}

// URL is the proxy's address. Set as the operator's HTTPS_PROXY /
// HTTP_PROXY env var to route Astinus traffic through it.
func (fp *FakeProxy) URL() string { return fp.server.URL }

// Close releases the underlying server.
func (fp *FakeProxy) Close() {
	if fp == nil || fp.server == nil {
		return
	}
	fp.server.Close()
	fp.server = nil
}

// RequestCount returns the number of requests the proxy saw.
func (fp *FakeProxy) RequestCount() int64 {
	if fp == nil {
		return 0
	}
	return atomic.LoadInt64(&fp.requests)
}

// LastAuthHeader returns the most recent `Authorization` header
// value the proxy received. Useful for asserting that
// `https://user:pass@proxy:8080`-style URLs propagate the
// credentials correctly.
func (fp *FakeProxy) LastAuthHeader() string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.lastAuth
}

// handle is the single proxy handler. It records the request, then
// forwards to upstream verbatim (URL.Path-rebased onto upstream's
// host).
func (fp *FakeProxy) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&fp.requests, 1)
	fp.mu.Lock()
	fp.lastAuth = r.Header.Get("Proxy-Authorization")
	if fp.lastAuth == "" {
		fp.lastAuth = r.Header.Get("Authorization")
	}
	fp.mu.Unlock()

	if r.Method == http.MethodConnect {
		http.Error(w, "fake proxy: CONNECT not supported (use plain HTTP for tests)", http.StatusBadGateway)
		return
	}

	target := fp.upstream.URL + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body) //nolint:gosec // test-only proxy; target is the upstream the test owns
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()
	resp, err := fp.upstream.Client().Do(req) //nolint:gosec // upstream is the test fixture's httptest.Server
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
