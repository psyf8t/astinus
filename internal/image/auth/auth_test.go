package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── EnvProvider ───────────────────────────────────────────────────────────

func TestEnvProviderGenericVars(t *testing.T) {
	p := &EnvProvider{getenv: stubEnv(map[string]string{
		"REGISTRY_USERNAME": "alice",
		"REGISTRY_PASSWORD": "s3cret",
	})}
	c, err := p.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "alice" || c.Password != "s3cret" {
		t.Errorf("creds = %+v", c)
	}
}

func TestEnvProviderPerHostBeatsGeneric(t *testing.T) {
	p := &EnvProvider{getenv: stubEnv(map[string]string{
		"REGISTRY_USERNAME":                 "generic",
		"REGISTRY_PASSWORD":                 "generic",
		"ASTINUS_REGISTRY_GHCR_IO_USERNAME": "perhost-user",
		"ASTINUS_REGISTRY_GHCR_IO_PASSWORD": "perhost-pass",
	})}
	c, err := p.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "perhost-user" || c.Password != "perhost-pass" {
		t.Errorf("expected per-host to win; got %+v", c)
	}
}

func TestEnvProviderTokenOnly(t *testing.T) {
	p := &EnvProvider{getenv: stubEnv(map[string]string{
		"REGISTRY_TOKEN": "bearer-xyz",
	})}
	c, err := p.Resolve(context.Background(), "harbor.corp.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Token != "bearer-xyz" {
		t.Errorf("token = %q, want bearer-xyz", c.Token)
	}
}

func TestEnvProviderNoCreds(t *testing.T) {
	p := &EnvProvider{getenv: stubEnv(map[string]string{})}
	_, err := p.Resolve(context.Background(), "ghcr.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestEnvHostKey(t *testing.T) {
	cases := map[string]string{
		"ghcr.io":               "GHCR_IO",
		"artifactory.corp.com":  "ARTIFACTORY_CORP_COM",
		"my-registry-1.example": "MY_REGISTRY_1_EXAMPLE",
		"localhost:5000":        "LOCALHOST_5000",
	}
	for in, want := range cases {
		if got := envHostKey(in); got != want {
			t.Errorf("envHostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── DockerConfigProvider ──────────────────────────────────────────────────

func TestDockerConfigProviderAuthField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"ghcr.io": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("alice:s3cret")) + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewDockerConfigProviderAt(path)
	c, err := p.Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "alice" || c.Password != "s3cret" {
		t.Errorf("creds = %+v", c)
	}
}

func TestDockerConfigProviderUsernamePasswordFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"ghcr.io": {"username": "bob", "password": "pwd"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "bob" || c.Password != "pwd" {
		t.Errorf("creds = %+v", c)
	}
}

func TestDockerConfigProviderRegistryToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"ghcr.io": {"registrytoken": "bearer-xyz", "identitytoken": "refresh"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Token != "bearer-xyz" || c.IdentityToken != "refresh" {
		t.Errorf("creds = %+v", c)
	}
}

func TestDockerConfigProviderHostMatchSchemeStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"https://index.docker.io/v1/": {"username": "u", "password": "p"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "index.docker.io")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "u" || c.Password != "p" {
		t.Errorf("creds = %+v", c)
	}
}

func TestDockerConfigProviderMissingFile(t *testing.T) {
	p := NewDockerConfigProviderAt("/no/such/config.json")
	_, err := p.Resolve(context.Background(), "ghcr.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestDockerConfigProviderNoEntryForHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"other.host": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("u:p")) + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestDockerConfigProviderMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if err == nil {
		t.Fatal("expected error for malformed config")
	}
	if errors.Is(err, ErrNoCredentials) {
		t.Fatalf("malformed config should not be ErrNoCredentials, got %v", err)
	}
}

func TestDockerConfigProviderInvalidBase64Auth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"ghcr.io": {"auth": "not-base64-?!"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if err == nil {
		t.Fatal("expected error for malformed auth field")
	}
}

func TestDockerConfigProviderAuthFieldMissingColon(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"auths": {"ghcr.io": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("nocolon")) + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewDockerConfigProviderAt(path).Resolve(context.Background(), "ghcr.io")
	if err == nil {
		t.Fatal("expected error for auth without colon")
	}
}

// ─── Chain ────────────────────────────────────────────────────────────────

type stubProvider struct {
	name   string
	creds  Credentials
	err    error
	called bool
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Resolve(_ context.Context, _ string) (Credentials, error) {
	s.called = true
	return s.creds, s.err
}

func TestChainFirstSuccessWins(t *testing.T) {
	p1 := &stubProvider{name: "p1", err: ErrNoCredentials}
	p2 := &stubProvider{name: "p2", creds: Credentials{Username: "u", Password: "p"}}
	p3 := &stubProvider{name: "p3"}
	c, err := NewChain(p1, p2, p3).Resolve(context.Background(), "host")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Username != "u" {
		t.Errorf("creds = %+v", c)
	}
	if !p1.called || !p2.called {
		t.Error("p1 and p2 should both be called")
	}
	if p3.called {
		t.Error("p3 should NOT be called once p2 succeeded")
	}
}

func TestChainEmptyReturnsErrNoCredentials(t *testing.T) {
	_, err := NewChain().Resolve(context.Background(), "host")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestChainAllNoCreds(t *testing.T) {
	p1 := &stubProvider{name: "p1", err: ErrNoCredentials}
	p2 := &stubProvider{name: "p2", err: ErrNoCredentials}
	_, err := NewChain(p1, p2).Resolve(context.Background(), "host")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestChainHardErrorHaltsIteration(t *testing.T) {
	p1 := &stubProvider{name: "p1", err: errors.New("config corrupt")}
	p2 := &stubProvider{name: "p2", creds: Credentials{Username: "u"}}
	_, err := NewChain(p1, p2).Resolve(context.Background(), "host")
	if err == nil {
		t.Fatal("expected hard error")
	}
	if errors.Is(err, ErrNoCredentials) {
		t.Fatalf("hard error should not be ErrNoCredentials, got %v", err)
	}
	if p2.called {
		t.Error("p2 should NOT be called after hard error in p1")
	}
}

func TestChainAppendAndProviders(t *testing.T) {
	c := NewChain(&stubProvider{name: "first"})
	c.Append(&stubProvider{name: "second"})
	got := c.Providers()
	if len(got) != 2 || got[0].Name() != "first" || got[1].Name() != "second" {
		t.Errorf("providers = %v", got)
	}
	if !strings.Contains(c.Name(), "first") || !strings.Contains(c.Name(), "second") {
		t.Errorf("Name() = %q", c.Name())
	}
}

func TestDefaultChainOrder(t *testing.T) {
	c := DefaultChain()
	provs := c.Providers()
	got := make([]string, 0, len(provs))
	for _, p := range provs {
		got = append(got, p.Name())
	}
	want := []string{"env", "docker-config", "artifactory", "ecr", "gcr", "acr"}
	if len(got) != len(want) {
		t.Fatalf("DefaultChain length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("DefaultChain[%d] = %q, want %q (full: %v)", i, got[i], name, got)
		}
	}
}

func TestCredentialsIsEmpty(t *testing.T) {
	if !(Credentials{}).IsEmpty() {
		t.Error("zero credentials should be IsEmpty")
	}
	if (Credentials{Username: "x"}).IsEmpty() {
		t.Error("creds with username should not be IsEmpty")
	}
	if (Credentials{Token: "x"}).IsEmpty() {
		t.Error("creds with token should not be IsEmpty")
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func stubEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}
