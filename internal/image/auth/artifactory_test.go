package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestArtifactoryProviderTokenMode(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryToken, TokenEnv: "MY_TOKEN"},
		getenv: envFunc(map[string]string{"MY_TOKEN": "secret-token"}),
	}
	c, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Token != "secret-token" {
		t.Errorf("Token = %q", c.Token)
	}
	if c.Username != "" || c.Password != "" {
		t.Errorf("token mode should not populate user/pass: %+v", c)
	}
}

func TestArtifactoryProviderTokenFallbackToDefaultEnv(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryToken},
		getenv: envFunc(map[string]string{"ARTIFACTORY_TOKEN": "default-token"}),
	}
	c, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Token != "default-token" {
		t.Errorf("Token = %q (should fall back to ARTIFACTORY_TOKEN)", c.Token)
	}
}

func TestArtifactoryProviderTokenMissing(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryToken},
		getenv: envFunc(map[string]string{}),
	}
	_, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestArtifactoryProviderAPIKeyMode(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg: ArtifactoryConfig{
			Mode:    ArtifactoryAPIKey,
			UserEnv: "U", APIKeyEnv: "K",
		},
		getenv: envFunc(map[string]string{"U": "alice", "K": "AKCpa..."}),
	}
	c, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "alice" || c.Password != "AKCpa..." {
		t.Errorf("creds = %+v", c)
	}
}

func TestArtifactoryProviderAPIKeyMissing(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryAPIKey, UserEnv: "U", APIKeyEnv: "K"},
		getenv: envFunc(map[string]string{"U": "alice"}),
	}
	_, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestArtifactoryProviderOIDCMode(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryOIDC, OIDCTokenEnv: "GITHUB_TOKEN"},
		getenv: envFunc(map[string]string{"GITHUB_TOKEN": "github-jwt"}),
	}
	c, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Token != "github-jwt" {
		t.Errorf("Token = %q", c.Token)
	}
}

func TestArtifactoryProviderOIDCMissing(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryOIDC},
		getenv: envFunc(map[string]string{}),
	}
	_, err := p.Resolve(context.Background(), "artifactory.corp.com")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestArtifactoryProviderHostFilter(t *testing.T) {
	// Empty Hosts → heuristic: only hosts containing "artifactory".
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryToken},
		getenv: envFunc(map[string]string{"ARTIFACTORY_TOKEN": "x"}),
	}
	if _, err := p.Resolve(context.Background(), "ghcr.io"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("non-artifactory host should be out of scope, got %v", err)
	}
	if _, err := p.Resolve(context.Background(), "ARTIFACTORY.corp.com"); err != nil {
		t.Errorf("matching host should work case-insensitively: %v", err)
	}

	// Explicit Hosts list narrows further.
	p.cfg.Hosts = []string{"art.corp.com"}
	if _, err := p.Resolve(context.Background(), "artifactory.example.com"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("explicit Hosts should override heuristic: %v", err)
	}
	if _, err := p.Resolve(context.Background(), "art.corp.com"); err != nil {
		t.Errorf("explicit host match: %v", err)
	}
}

func TestArtifactoryProviderName(t *testing.T) {
	if NewArtifactoryProvider(ArtifactoryConfig{}).Name() != "artifactory" {
		t.Error("Name")
	}
}

func TestReadEnvFallbackPrecedence(t *testing.T) {
	get := envFunc(map[string]string{"A": "", "B": "  trimmed-b  ", "C": "c"})
	if got := readEnvFallback(get, "A", "B", "C"); got != "trimmed-b" {
		t.Errorf("got %q", got)
	}
	if got := readEnvFallback(get, "", "missing"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestArtifactoryUnknownModeDecorationIncludesNumber(t *testing.T) {
	p := &ArtifactoryProvider{
		cfg:    ArtifactoryConfig{Mode: ArtifactoryMode(99)},
		getenv: envFunc(nil),
	}
	_, err := p.Resolve(context.Background(), "artifactory.x")
	if err == nil || !strings.Contains(err.Error(), "99") {
		t.Errorf("err = %v, expected to mention mode 99", err)
	}
}
