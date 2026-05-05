package transport

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// PerRegistry is an http.RoundTripper that dispatches requests to
// per-host transports based on req.URL.Host. Hosts without an
// explicit override fall back to a configured default transport.
//
// Construction model: build the default transport via New(...), build
// per-host transports via New(...) too, then assemble a PerRegistry
// with NewPerRegistry. The whole tree honours go-containerregistry's
// remote.WithTransport contract — pass the *PerRegistry directly.
type PerRegistry struct {
	mu    sync.RWMutex
	def   http.RoundTripper
	hosts map[string]http.RoundTripper
}

// NewPerRegistry returns a PerRegistry whose default is def.
//
// def MUST NOT be nil — every request needs SOMETHING to route
// against. Per-host transports are added via Set.
func NewPerRegistry(def http.RoundTripper) (*PerRegistry, error) {
	if def == nil {
		return nil, fmt.Errorf("transport: per-registry default is required")
	}
	return &PerRegistry{def: def, hosts: map[string]http.RoundTripper{}}, nil
}

// Set registers transport rt for host (case-insensitive). Replaces
// any prior entry for the same host.
func (p *PerRegistry) Set(host string, rt http.RoundTripper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hosts[normalizeHost(host)] = rt
}

// Hosts returns the set of host overrides currently registered. Used
// for log lines / tests.
func (p *PerRegistry) Hosts() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.hosts))
	for k := range p.hosts {
		out = append(out, k)
	}
	return out
}

// RoundTrip implements http.RoundTripper.
func (p *PerRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("transport: nil request/url")
	}
	p.mu.RLock()
	rt, ok := p.hosts[normalizeHost(req.URL.Host)]
	p.mu.RUnlock()
	if !ok {
		rt = p.def
	}
	return rt.RoundTrip(req)
}

// normalizeHost lowercases host and trims surrounding whitespace.
// "host:port" stays distinct from "host" — matches OCI distribution
// behaviour and the auth.envHostKey policy from Stage 2.
func normalizeHost(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
