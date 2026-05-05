//go:build acceptance

package helpers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// FakeNpmMirror simulates a corporate npm mirror (Artifactory's
// `npm-virtual` or a Verdaccio cache). Constructor takes a
// per-package payload map; requests for unknown paths return 404.
//
// AuthFunc, when non-nil, gates every request — return false to
// emit a 401. Used by the auth-failure test to drive the graceful-
// degradation path.
type FakeNpmMirror struct {
	server   *httptest.Server
	requests int64
	hits     int64
	misses   int64
	authOK   atomic.Bool
	pkgs     map[string][]byte
	authFunc func(r *http.Request) bool
}

// NewFakeNpmMirror starts a mirror serving the supplied per-path
// JSON payloads. Caller defers Close.
func NewFakeNpmMirror(tb testing.TB, pkgs map[string][]byte) *FakeNpmMirror {
	tb.Helper()
	m := &FakeNpmMirror{pkgs: pkgs}
	m.authOK.Store(true)
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	tb.Cleanup(m.Close)
	return m
}

// URL returns the mirror's base URL (operator points
// `--mirrors-config` at this).
func (m *FakeNpmMirror) URL() string { return m.server.URL }

// Server is the underlying httptest.Server. Exposed so a FakeProxy
// can be wired up in front of it (the proxy needs the server's
// `Client()` to honour any TLS knobs the test set on the server).
func (m *FakeNpmMirror) Server() *httptest.Server { return m.server }

// Close releases the underlying server.
func (m *FakeNpmMirror) Close() {
	if m == nil || m.server == nil {
		return
	}
	m.server.Close()
	m.server = nil
}

// RequestCount returns the total number of requests the mirror has
// observed (hits + misses + auth-rejects).
func (m *FakeNpmMirror) RequestCount() int64 { return atomic.LoadInt64(&m.requests) }

// Hits returns the count of requests the mirror served from its
// payload map.
func (m *FakeNpmMirror) Hits() int64 { return atomic.LoadInt64(&m.hits) }

// Misses returns the count of requests for paths the mirror did not
// have a payload for (404 responses).
func (m *FakeNpmMirror) Misses() int64 { return atomic.LoadInt64(&m.misses) }

// SetAuthFunc installs a per-request gate. Return false to emit
// 401 (used to test corporate auth-failure handling).
func (m *FakeNpmMirror) SetAuthFunc(fn func(r *http.Request) bool) {
	m.authFunc = fn
}

// SpyServer is the simpler alternative — just counts requests
// without serving payloads. Used to assert "this endpoint MUST
// NOT be called" in the mirror-replace-mode test.
type SpyServer struct {
	server   *httptest.Server
	requests int64
}

// NewSpyServer starts a server that counts every request and
// returns 404. Caller defers Close.
func NewSpyServer(tb testing.TB) *SpyServer {
	tb.Helper()
	s := &SpyServer{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&s.requests, 1)
		http.NotFound(w, nil)
	}))
	tb.Cleanup(s.Close)
	return s
}

// URL is the spy's address.
func (s *SpyServer) URL() string { return s.server.URL }

// Close releases the underlying server.
func (s *SpyServer) Close() {
	if s == nil || s.server == nil {
		return
	}
	s.server.Close()
	s.server = nil
}

// RequestCount returns the number of requests the spy has seen.
func (s *SpyServer) RequestCount() int64 {
	if s == nil {
		return 0
	}
	return atomic.LoadInt64(&s.requests)
}

// handle is the npm-mirror request dispatcher. Strips the
// Artifactory-style `/api/npm/<repo>` prefix when present so the
// same payload map works for both bare-mirror and Artifactory
// shapes.
func (m *FakeNpmMirror) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.requests, 1)
	if m.authFunc != nil && !m.authFunc(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := stripMirrorPrefix(r.URL.Path)
	body, ok := m.pkgs[path]
	if !ok {
		atomic.AddInt64(&m.misses, 1)
		http.NotFound(w, r)
		return
	}
	atomic.AddInt64(&m.hits, 1)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// stripMirrorPrefix normalises the Artifactory / Nexus / GitHub-
// Packages mirror path conventions to a bare `/<package>/<version>`
// shape so the test fixture map stays small.
func stripMirrorPrefix(p string) string {
	for _, prefix := range []string{
		"/api/npm/npm-virtual",
		"/api/npm/npm-public",
		"/repository/npm-proxy",
	} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix)
		}
	}
	return p
}

// LodashPackageJSON is a minimal but realistic npm registry
// per-version payload for `lodash@4.17.20`. Used across the
// corporate-scenario tests so each suite doesn't reinvent the
// fixture.
func LodashPackageJSON() []byte {
	return []byte(`{
		"name": "lodash",
		"version": "4.17.20",
		"description": "Lodash modular utilities.",
		"license": "MIT",
		"homepage": "https://lodash.com/",
		"repository": {"type": "git", "url": "git+https://github.com/lodash/lodash.git"},
		"author": "John-David Dalton <john@example.com>",
		"dist": {"shasum": "deadbeef", "integrity": "sha512-aGVsbG8="}
	}`)
}

// ExpressPackageJSON is the matching fixture for `express@4.17.0`.
func ExpressPackageJSON() []byte {
	return []byte(`{
		"name": "express",
		"version": "4.17.0",
		"description": "Fast, unopinionated, minimalist web framework.",
		"license": "MIT",
		"homepage": "http://expressjs.com/",
		"repository": {"type": "git", "url": "git+https://github.com/expressjs/express.git"},
		"author": "TJ Holowaychuk <tj@vision-media.ca>"
	}`)
}
