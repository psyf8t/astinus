package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	body := []byte(`
version: 1
registries:
  - host: artifactory.corp.com
    auth:
      type: artifactory-token
      token-env: ARTIFACTORY_TOKEN
    tls:
      ca-cert: /etc/ssl/artifactory-ca.pem
      client-cert: /etc/ssl/client.crt
      client-key: /etc/ssl/client.key
  - host: harbor.corp.com
    auth:
      type: basic
      username-env: HARBOR_USER
      password-env: HARBOR_PASS
`)
	c, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Registries) != 2 {
		t.Fatalf("registries = %d", len(c.Registries))
	}
	if c.Registries[0].Host != "artifactory.corp.com" {
		t.Errorf("Host = %q", c.Registries[0].Host)
	}
	if c.Registries[0].Auth.Type != "artifactory-token" {
		t.Errorf("Auth.Type = %q", c.Registries[0].Auth.Type)
	}
	if c.Registries[0].TLS.CACert != "/etc/ssl/artifactory-ca.pem" {
		t.Errorf("TLS.CACert = %q", c.Registries[0].TLS.CACert)
	}
}

func TestParseRejectsMissingHost(t *testing.T) {
	body := []byte(`registries:
  - auth: {type: basic}`)
	_, err := Parse(body)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Errorf("err = %v", err)
	}
}

func TestParseRejectsHalfClientCert(t *testing.T) {
	body := []byte(`registries:
  - host: x.corp.com
    tls:
      client-cert: /etc/ssl/x.crt`)
	_, err := Parse(body)
	if err == nil || !strings.Contains(err.Error(), "client-cert and client-key") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "astinus.yaml")
	body := []byte("registries:\n  - host: x.corp.com\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Registries) != 1 || c.Registries[0].Host != "x.corp.com" {
		t.Errorf("got = %+v", c.Registries)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/no/such/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFindRegistryCaseInsensitive(t *testing.T) {
	c := &Config{Registries: []RegistryConfig{{Host: "Artifactory.CORP.com"}}}
	if r := c.FindRegistry("artifactory.corp.com"); r == nil {
		t.Fatal("FindRegistry should match case-insensitively")
	}
	if r := c.FindRegistry("other.host"); r != nil {
		t.Errorf("FindRegistry should miss for unmatched host")
	}
}

func TestFindRegistryNilSafe(t *testing.T) {
	var c *Config
	if r := c.FindRegistry("anything"); r != nil {
		t.Errorf("nil Config should yield nil Registry")
	}
}

func TestHasPerRegistryTLS(t *testing.T) {
	c := &Config{Registries: []RegistryConfig{{Host: "x"}}}
	if c.HasPerRegistryTLS() {
		t.Error("plain host should NOT count")
	}
	c.Registries[0].TLS = &TLSConfig{CACert: "/etc/ssl/ca.pem"}
	if !c.HasPerRegistryTLS() {
		t.Error("CA cert should count")
	}

	c2 := &Config{Registries: []RegistryConfig{{Host: "y", Insecure: true}}}
	if !c2.HasPerRegistryTLS() {
		t.Error("Insecure should count")
	}

	c3 := &Config{Registries: []RegistryConfig{{Host: "z", Proxy: "http://x"}}}
	if !c3.HasPerRegistryTLS() {
		t.Error("Proxy should count")
	}

	var nilc *Config
	if nilc.HasPerRegistryTLS() {
		t.Error("nil Config should be false")
	}
}
