package sign

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyOptionsValidate(t *testing.T) {
	cases := []struct {
		name string
		opts VerifyOptions
		want bool // true = expect error
	}{
		{"detached + key OK",
			VerifyOptions{
				SBOMPath: "/tmp/sbom", SignaturePath: "/tmp/sig", KeyPath: "/tmp/key",
			}, false},
		{"image-attached + keyless OK",
			VerifyOptions{
				AttachedToImage:    "img:v1",
				CertIdentityRegexp: ".*",
				CertOIDCIssuer:     "https://example.com",
			}, false},
		{"both image + signature error",
			VerifyOptions{
				AttachedToImage: "img:v1", SignaturePath: "/tmp/sig", KeyPath: "/tmp/key",
			}, true},
		{"neither image nor signature",
			VerifyOptions{KeyPath: "/tmp/key"}, true},
		{"signature without sbom",
			VerifyOptions{SignaturePath: "/tmp/sig", KeyPath: "/tmp/key"}, true},
		{"no auth method",
			VerifyOptions{SBOMPath: "/tmp/sbom", SignaturePath: "/tmp/sig"}, true},
		{"keyless half-set",
			VerifyOptions{
				AttachedToImage:    "img:v1",
				CertIdentityRegexp: ".*",
			}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.opts.validate()
			if (err != nil) != c.want {
				t.Errorf("validate = %v, want err? %v", err, c.want)
			}
		})
	}
}

func TestNewVerifier_ErrToolingWhenMissing(t *testing.T) {
	_, err := NewVerifier(CosignOptions{CosignPath: "/no/such/cosign-binary"})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !errors.Is(err, ErrTooling) {
		t.Errorf("err = %v, want wraps ErrTooling", err)
	}
}

func TestVerifier_VerifyBlob(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	v, err := NewVerifier(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	sig := filepath.Join(dir, "sbom.sig")
	key := filepath.Join(dir, "cosign.pub")
	res, err := v.Verify(context.Background(), VerifyOptions{
		SBOMPath:      sbom,
		SignaturePath: sig,
		KeyPath:       key,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	log := readMockLog(t, logPath)
	for _, want := range []string{
		"verify-blob",
		"--signature " + sig,
		"--key " + key,
		sbom,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("argv missing %q\nfull log:\n%s", want, log)
		}
	}
}

func TestVerifier_VerifyAttestationKeyless(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	v, err := NewVerifier(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), VerifyOptions{
		AttachedToImage:    "ghcr.io/test/img:v1",
		CertIdentityRegexp: "^https://github.com/myorg/.*",
		CertOIDCIssuer:     "https://token.actions.githubusercontent.com",
		RekorURL:           "https://rekor.corp",
	})
	if err != nil {
		t.Fatal(err)
	}
	log := readMockLog(t, logPath)
	for _, want := range []string{
		"verify-attestation",
		"--certificate-identity-regexp ^https://github.com/myorg/.*",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"ghcr.io/test/img:v1",
		"REKOR=https://rekor.corp",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("argv/env missing %q\nfull log:\n%s", want, log)
		}
	}
}

func TestVerifier_FailingCosignReturnsErrSigning(t *testing.T) {
	mockPath, _ := writeMockCosign(t)
	t.Setenv("MOCK_COSIGN_FAIL", "1")
	v, err := NewVerifier(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), VerifyOptions{
		SBOMPath:      filepath.Join(t.TempDir(), "sbom"),
		SignaturePath: filepath.Join(t.TempDir(), "sig"),
		KeyPath:       filepath.Join(t.TempDir(), "key"),
	})
	if err == nil {
		t.Fatal("expected error from failing cosign")
	}
	if !errors.Is(err, ErrSigning) {
		t.Errorf("err = %v, want wraps ErrSigning", err)
	}
}

func TestCosignVersion_Returns(t *testing.T) {
	mockPath, _ := writeMockCosign(t)
	got, err := CosignVersion(context.Background(), CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatalf("CosignVersion: %v", err)
	}
	if got == "" {
		t.Errorf("expected non-empty version output")
	}
}
