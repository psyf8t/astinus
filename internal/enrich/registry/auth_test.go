package registry

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/config"
)

func TestApplyAuth_NilSkips(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err := applyAuth(req, nil); err != nil {
		t.Fatalf("nil auth must be a no-op, got: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Errorf("nil auth set Authorization header: %q", req.Header.Get("Authorization"))
	}
}

func TestApplyAuth_BearerLiteral(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{
		Type:  "bearer",
		Token: "literal-token-123",
	})
	if err != nil {
		t.Fatalf("applyAuth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer literal-token-123" {
		t.Errorf("Authorization = %q, want Bearer literal-token-123", got)
	}
}

// TestApplyAuth_BearerEnv exercises the secret-from-env path —
// the security default for corp configs that never store
// credentials in YAML.
func TestApplyAuth_BearerEnv(t *testing.T) {
	t.Setenv("ASTINUS_TEST_BEARER", "env-secret-xyz")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{
		Type:     "bearer",
		TokenEnv: "ASTINUS_TEST_BEARER",
	})
	if err != nil {
		t.Fatalf("applyAuth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer env-secret-xyz" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestApplyAuth_BearerEmptyEnvErrors(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{
		Type:     "bearer",
		TokenEnv: "ASTINUS_TEST_NEVER_SET",
	})
	if err == nil {
		t.Fatal("empty env var should error (operator misconfiguration)")
	}
}

func TestApplyAuth_BasicEnv(t *testing.T) {
	t.Setenv("ASTINUS_TEST_PASS", "p@ss!")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{
		Type:        "basic",
		Username:    "buildbot",
		PasswordEnv: "ASTINUS_TEST_PASS",
	})
	if err != nil {
		t.Fatalf("applyAuth: %v", err)
	}
	user, pass, ok := req.BasicAuth()
	if !ok {
		t.Fatal("basic auth not set")
	}
	if user != "buildbot" || pass != "p@ss!" {
		t.Errorf("user=%q pass=%q", user, pass)
	}
}

func TestApplyAuth_HeaderEnv_JFrog(t *testing.T) {
	// Reproduces the JFrog X-JFrog-Art-Api header pattern that
	// Artifactory instances use for API-key auth.
	t.Setenv("ASTINUS_TEST_JFROG", "AKCp1234567890")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{
		Type:           "header",
		HeaderName:     "X-JFrog-Art-Api",
		HeaderValueEnv: "ASTINUS_TEST_JFROG",
	})
	if err != nil {
		t.Fatalf("applyAuth: %v", err)
	}
	if got := req.Header.Get("X-JFrog-Art-Api"); got != "AKCp1234567890" {
		t.Errorf("X-JFrog-Art-Api = %q", got)
	}
}

func TestApplyAuth_UnknownTypeErrors(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	err := applyAuth(req, &config.MirrorAuthConfig{Type: "saml"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-type error, got: %v", err)
	}
}

func TestApplyHeaders_ExpandsEnvReferences(t *testing.T) {
	t.Setenv("ASTINUS_TEST_HEADER_VAL", "value-from-env")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyHeaders(req, map[string]string{
		"X-Literal": "literal",
		"X-FromEnv": "${ASTINUS_TEST_HEADER_VAL}",
	})
	if got := req.Header.Get("X-Literal"); got != "literal" {
		t.Errorf("X-Literal = %q", got)
	}
	if got := req.Header.Get("X-FromEnv"); got != "value-from-env" {
		t.Errorf("X-FromEnv = %q", got)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"https://artifactory.corp/api/npm": "artifactory.corp",
		"https://nexus.corp:8443/path?x=1": "nexus.corp:8443",
		"http://example.com":               "example.com",
		"weirdurl-no-scheme":               "weirdurl-no-scheme",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
