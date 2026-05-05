package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMirrorsConfig_Minimal(t *testing.T) {
	cfg, err := ParseMirrorsConfig([]byte(`
mirrors:
  - ecosystem: npm
    url: https://artifactory.corp/api/npm
    mode: replace
    auth:
      type: bearer
      token_env: ARTIFACTORY_TOKEN
`))
	if err != nil {
		t.Fatalf("ParseMirrorsConfig: %v", err)
	}
	if len(cfg.Mirrors) != 1 {
		t.Fatalf("mirrors len = %d, want 1", len(cfg.Mirrors))
	}
	m := cfg.Mirrors[0]
	if m.Ecosystem != "npm" || m.Mode != MirrorModeReplace {
		t.Errorf("entry = %+v", m)
	}
	if m.Auth == nil || m.Auth.TokenEnv != "ARTIFACTORY_TOKEN" {
		t.Errorf("auth = %+v", m.Auth)
	}
}

func TestParseMirrorsConfig_DefaultModeIsReplace(t *testing.T) {
	cfg, err := ParseMirrorsConfig([]byte(`
mirrors:
  - ecosystem: pypi
    url: https://nexus.corp/repository/pypi-proxy
`))
	if err != nil {
		t.Fatalf("ParseMirrorsConfig: %v", err)
	}
	// Empty Mode is acceptable (treated as replace by EffectiveMode).
	if !cfg.Mirrors[0].Mode.IsKnown() {
		t.Errorf("empty mode should be known (treated as replace)")
	}
	if cfg.Mirrors[0].Mode.EffectiveMode() != MirrorModeReplace {
		t.Errorf("EffectiveMode = %q, want replace", cfg.Mirrors[0].Mode.EffectiveMode())
	}
}

func TestParseMirrorsConfig_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing ecosystem", `mirrors: [{url: https://x.com}]`},
		{"missing url", `mirrors: [{ecosystem: npm}]`},
		{"unknown mode", `mirrors: [{ecosystem: npm, url: https://x.com, mode: unknown}]`},
		{"bearer no token",
			`mirrors:
  - ecosystem: npm
    url: https://x.com
    auth: {type: bearer}
`},
		{"basic no username",
			`mirrors:
  - ecosystem: npm
    url: https://x.com
    auth: {type: basic, password_env: P}
`},
		{"header no name",
			`mirrors:
  - ecosystem: npm
    url: https://x.com
    auth: {type: header, header_value: V}
`},
		{"unknown auth type",
			`mirrors:
  - ecosystem: npm
    url: https://x.com
    auth: {type: saml}
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMirrorsConfig([]byte(c.yaml))
			if err == nil {
				t.Errorf("expected validation error, got nil")
			}
		})
	}
}

func TestLoadMirrorsConfig_EmptyPath(t *testing.T) {
	cfg, err := LoadMirrorsConfig("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if len(cfg.Mirrors) != 0 {
		t.Errorf("expected empty config, got %d mirrors", len(cfg.Mirrors))
	}
}

func TestLoadMirrorsConfig_FromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrors.yaml")
	if err := os.WriteFile(path, []byte(`
mirrors:
  - ecosystem: maven
    url: https://maven.corp/repo
    mode: fallback
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadMirrorsConfig(path)
	if err != nil {
		t.Fatalf("LoadMirrorsConfig: %v", err)
	}
	if len(cfg.Mirrors) != 1 || cfg.Mirrors[0].Mode != MirrorModeFallback {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadMirrorsConfig_MissingFile(t *testing.T) {
	_, err := LoadMirrorsConfig("/no/such/file.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadMirrorsConfig_MalformedYAML(t *testing.T) {
	_, err := ParseMirrorsConfig([]byte("not: valid: yaml: at: all"))
	if err == nil || !strings.Contains(err.Error(), "parse YAML") {
		t.Errorf("expected parse error, got: %v", err)
	}
}
