package auth

import (
	"context"
	"fmt"
	"strings"
)

// cloudStubProvider is the shared shape behind ECRProvider /
// GCRProvider / ACRProvider. All three:
//
//   - recognise a host pattern,
//   - decline credentials with a HELPFUL error that points the
//     operator at the working alternative (Docker Config from
//     Stage 2, or per-host env vars from Stage 2),
//   - exist as registration anchors so a downstream fork that
//     embeds the relevant cloud SDK can substitute a real provider
//     in DefaultChain() without touching call sites.
//
// Stage 9 deliberately ships the stubs instead of pulling in the
// 30-MB triplet of cloud SDKs (AWS + GCP + Azure). ADR-0011
// documents the trade-off.
type cloudStubProvider struct {
	name      string
	hostMatch func(string) bool
	hint      string
}

func (p *cloudStubProvider) Name() string { return p.name }

func (p *cloudStubProvider) Resolve(_ context.Context, host string) (Credentials, error) {
	if !p.hostMatch(strings.ToLower(host)) {
		return Credentials{}, fmt.Errorf("%s: host %q out of scope: %w", p.name, host, ErrNoCredentials)
	}
	return Credentials{}, fmt.Errorf("%s: no built-in credentials helper for %q (%s): %w",
		p.name, host, p.hint, ErrNoCredentials)
}

// ECRProvider is the AWS Elastic Container Registry stub. Real
// credential acquisition uses the AWS SDK (`aws ecr
// get-authorization-token`); see ADR-0011 for the future SDK plug-in
// path.
type ECRProvider struct{ inner cloudStubProvider }

// NewECRProvider returns the canonical ECR stub.
func NewECRProvider() *ECRProvider {
	return &ECRProvider{inner: cloudStubProvider{
		name:      "ecr",
		hostMatch: hostLooksLikeECR,
		hint:      `run "aws ecr get-login-password | docker login" or set ASTINUS_REGISTRY_<HOST>_TOKEN`,
	}}
}

// Name implements CredentialProvider.
func (p *ECRProvider) Name() string { return p.inner.Name() }

// Resolve implements CredentialProvider.
func (p *ECRProvider) Resolve(ctx context.Context, host string) (Credentials, error) {
	return p.inner.Resolve(ctx, host)
}

// hostLooksLikeECR matches `<account>.dkr.ecr.<region>.amazonaws.com`.
func hostLooksLikeECR(host string) bool {
	return strings.Contains(host, ".dkr.ecr.") && strings.HasSuffix(host, ".amazonaws.com")
}

// GCRProvider is the Google Container / Artifact Registry stub.
type GCRProvider struct{ inner cloudStubProvider }

// NewGCRProvider returns the canonical GCR/AR stub.
func NewGCRProvider() *GCRProvider {
	return &GCRProvider{inner: cloudStubProvider{
		name:      "gcr",
		hostMatch: hostLooksLikeGCR,
		hint:      `run "gcloud auth configure-docker" or set ASTINUS_REGISTRY_<HOST>_TOKEN`,
	}}
}

// Name implements CredentialProvider.
func (p *GCRProvider) Name() string { return p.inner.Name() }

// Resolve implements CredentialProvider.
func (p *GCRProvider) Resolve(ctx context.Context, host string) (Credentials, error) {
	return p.inner.Resolve(ctx, host)
}

// hostLooksLikeGCR covers gcr.io, *.gcr.io, *.pkg.dev (Artifact Registry).
func hostLooksLikeGCR(host string) bool {
	switch {
	case host == "gcr.io", strings.HasSuffix(host, ".gcr.io"):
		return true
	case strings.HasSuffix(host, ".pkg.dev"):
		return true
	}
	return false
}

// ACRProvider is the Azure Container Registry stub.
type ACRProvider struct{ inner cloudStubProvider }

// NewACRProvider returns the canonical ACR stub.
func NewACRProvider() *ACRProvider {
	return &ACRProvider{inner: cloudStubProvider{
		name:      "acr",
		hostMatch: hostLooksLikeACR,
		hint:      `run "az acr login --name <registry>" or set ASTINUS_REGISTRY_<HOST>_TOKEN`,
	}}
}

// Name implements CredentialProvider.
func (p *ACRProvider) Name() string { return p.inner.Name() }

// Resolve implements CredentialProvider.
func (p *ACRProvider) Resolve(ctx context.Context, host string) (Credentials, error) {
	return p.inner.Resolve(ctx, host)
}

// hostLooksLikeACR matches *.azurecr.io.
func hostLooksLikeACR(host string) bool {
	return strings.HasSuffix(host, ".azurecr.io")
}
