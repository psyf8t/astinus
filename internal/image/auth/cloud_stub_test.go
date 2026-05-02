package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestECRStubMatchesECRHosts(t *testing.T) {
	p := NewECRProvider()
	if p.Name() != "ecr" {
		t.Errorf("Name = %q", p.Name())
	}

	// In-scope: returns ErrNoCredentials with helpful hint.
	_, err := p.Resolve(context.Background(), "123456789012.dkr.ecr.us-east-1.amazonaws.com")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "aws ecr get-login-password") {
		t.Errorf("error should mention the docker login workflow: %v", err)
	}

	// Out-of-scope: also ErrNoCredentials but with "out of scope" wording.
	_, err = p.Resolve(context.Background(), "artifactory.corp.com")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("error should mention out-of-scope: %v", err)
	}
}

func TestGCRStubMatchesGCRAndArtifactRegistry(t *testing.T) {
	p := NewGCRProvider()
	for _, host := range []string{
		"gcr.io",
		"us.gcr.io",
		"asia.gcr.io",
		"us-docker.pkg.dev",
		"europe-west1-docker.pkg.dev",
	} {
		_, err := p.Resolve(context.Background(), host)
		if !errors.Is(err, ErrNoCredentials) {
			t.Errorf("%s err = %v", host, err)
		}
		if !strings.Contains(err.Error(), "gcloud auth") {
			t.Errorf("%s missing hint: %v", host, err)
		}
	}

	// Out-of-scope: not a Google host.
	_, err := p.Resolve(context.Background(), "ghcr.io")
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("ghcr.io should be out of scope: %v", err)
	}
}

func TestACRStubMatchesACRHosts(t *testing.T) {
	p := NewACRProvider()
	_, err := p.Resolve(context.Background(), "myreg.azurecr.io")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "az acr login") {
		t.Errorf("missing hint: %v", err)
	}

	_, err = p.Resolve(context.Background(), "ghcr.io")
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("ghcr.io should be out of scope for ACR: %v", err)
	}
}

func TestHostLooksLikeECR(t *testing.T) {
	cases := map[string]bool{
		"123.dkr.ecr.us-east-1.amazonaws.com":      true,
		"123.dkr.ecr-fips.us-east-1.amazonaws.com": false,
		"ghcr.io": false,
		"":        false,
	}
	for host, want := range cases {
		if got := hostLooksLikeECR(host); got != want {
			t.Errorf("hostLooksLikeECR(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostLooksLikeGCR(t *testing.T) {
	cases := map[string]bool{
		"gcr.io":             true,
		"us.gcr.io":          true,
		"us-docker.pkg.dev":  true,
		"ghcr.io":            false,
		"docker.pkg.example": false,
	}
	for host, want := range cases {
		if got := hostLooksLikeGCR(host); got != want {
			t.Errorf("hostLooksLikeGCR(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostLooksLikeACR(t *testing.T) {
	if !hostLooksLikeACR("myreg.azurecr.io") {
		t.Error("missed azurecr.io")
	}
	if hostLooksLikeACR("ghcr.io") {
		t.Error("matched ghcr.io")
	}
}
