package cli

import (
	"net/http"
	"testing"
	"time"
)

// TestBuildCPESourceHTTPClient_HTTPTransportClonedWithHeaderTimeout —
// S7 Task 0 defense-in-depth. When the operator transport is a
// recognisable *http.Transport, the helper clones it and sets
// ResponseHeaderTimeout = callTimeout so a TCP connection that
// establishes but never sends response headers fails at the
// transport layer — independent of context propagation.
func TestBuildCPESourceHTTPClient_HTTPTransportClonedWithHeaderTimeout(t *testing.T) {
	tr := &http.Transport{}
	c := buildCPESourceHTTPClient(tr, 4*time.Second)
	if c == nil {
		t.Fatal("client is nil")
	}
	got, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", c.Transport)
	}
	if got == tr {
		t.Error("returned transport is the same instance — must be cloned")
	}
	if got.ResponseHeaderTimeout != 4*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 4s", got.ResponseHeaderTimeout)
	}
	// Client-level Timeout caps the entire request at
	// 2*callTimeout (max 60s).
	if c.Timeout != 8*time.Second {
		t.Errorf("client.Timeout = %v, want 8s (2*callTimeout)", c.Timeout)
	}
}

// TestBuildCPESourceHTTPClient_TimeoutCapAt60s pins the upper
// cap on the Client.Timeout. A long --cpe-call-timeout shouldn't
// translate into a multi-minute Client.Timeout (operator-visible
// surprise on slow CI runners).
func TestBuildCPESourceHTTPClient_TimeoutCapAt60s(t *testing.T) {
	c := buildCPESourceHTTPClient(&http.Transport{}, 45*time.Second)
	if c.Timeout != 60*time.Second {
		t.Errorf("client.Timeout = %v, want 60s (cap)", c.Timeout)
	}
}

// TestBuildCPESourceHTTPClient_UnknownTransportFallback covers the
// path where the operator transport isn't an *http.Transport
// directly (custom RoundTripper, future wrapper). The helper
// returns an unmodified client with a 30 s Client.Timeout.
func TestBuildCPESourceHTTPClient_UnknownTransportFallback(t *testing.T) {
	tr := &fakeRoundTripper{}
	c := buildCPESourceHTTPClient(tr, 5*time.Second)
	if c.Transport != tr {
		t.Errorf("fallback should keep the supplied transport; got %T", c.Transport)
	}
	if c.Timeout != 30*time.Second {
		t.Errorf("fallback Client.Timeout = %v, want 30s", c.Timeout)
	}
}

// TestBuildCPESourceHTTPClient_ZeroCallTimeoutDefault pins the
// defensive default when the operator passes 0 for the call
// timeout — the helper falls back to cpe.DefaultCallTimeout (10s).
func TestBuildCPESourceHTTPClient_ZeroCallTimeoutDefault(t *testing.T) {
	c := buildCPESourceHTTPClient(&http.Transport{}, 0)
	got, _ := c.Transport.(*http.Transport)
	if got == nil {
		t.Fatal("transport not cloned")
	}
	if got.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 10s (DefaultCallTimeout)",
			got.ResponseHeaderTimeout)
	}
}

// TestCapDuration pins the helper's ceiling clamping logic.
func TestCapDuration(t *testing.T) {
	cases := []struct {
		d, ceiling, want time.Duration
	}{
		{5 * time.Second, 10 * time.Second, 5 * time.Second},
		{10 * time.Second, 10 * time.Second, 10 * time.Second},
		{15 * time.Second, 10 * time.Second, 10 * time.Second},
		{0, 10 * time.Second, 0},
	}
	for _, c := range cases {
		if got := capDuration(c.d, c.ceiling); got != c.want {
			t.Errorf("capDuration(%v, %v) = %v, want %v", c.d, c.ceiling, got, c.want)
		}
	}
}

// fakeRoundTripper is a no-op RoundTripper used to exercise the
// "transport not an *http.Transport" fallback branch.
type fakeRoundTripper struct{}

func (*fakeRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, http.ErrUseLastResponse
}
