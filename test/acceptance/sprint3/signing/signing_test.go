//go:build acceptance

package signing

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestSigning_MissingCosignBinary — when --sign-with is set but the
// cosign binary path doesn't resolve, astinus exits 50 (ExitSigning)
// with an error that mentions cosign. This is the operator-facing
// hint that the install step was skipped; we'd rather hard-fail
// than silently produce an unsigned SBOM the operator believes is
// signed.
//
// We force the failure by passing --cosign-path at a path that
// doesn't exist. No real cosign install required.
func TestSigning_MissingCosignBinary(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)
	sigOut := filepath.Join(t.TempDir(), "out.sig")

	res := helpers.RunEnrich(t, helpers.EnrichOpts{
		SBOM:            sbom,
		Image:           "test/sign-missing-cosign:1.0",
		SignWith:        "cosign-key",
		SigningKey:      "/tmp/does-not-exist.key",
		SignatureOutput: sigOut,
		CosignPath:      "/non/existent/cosign-binary-xyz",
		Extra: []string{
			"--disable", "layer", "--disable", "evidence",
			"--no-network",
		},
	})

	if res.ExitCode != 50 {
		t.Fatalf("expected ExitSigning(50), got %d\nstderr:\n%s",
			res.ExitCode, res.Stderr)
	}
	if !strings.Contains(strings.ToLower(res.Stderr), "cosign") {
		t.Errorf("stderr should mention cosign; got:\n%s", res.Stderr)
	}
}

// TestSigning_KeyRoundTrip — full sign + verify roundtrip with a
// throwaway cosign key pair. Skips when cosign is not on PATH —
// developer machines often don't have it; CI does.
//
// We use cosign's own `generate-key-pair` to avoid pinning a
// specific key format.
func TestSigning_KeyRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cosign roundtrip uses POSIX path conventions; skipping on Windows")
	}
	requireCosignOnPath(t)

	dir := t.TempDir()
	keyPath, pubPath := generateCosignKeyPair(t, dir)

	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)
	sigOut := filepath.Join(dir, "sbom.sig")
	bomOut := filepath.Join(dir, "out.cdx.json")

	helpers.SetEnv(t, "COSIGN_PASSWORD", "")

	signRes := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:                  sbom,
		Image:                 "test/sign-roundtrip:1.0",
		SignWith:              "cosign-key",
		SigningKey:            keyPath,
		SigningKeyPasswordEnv: "COSIGN_PASSWORD",
		SignatureOutput:       sigOut,
		Output:                bomOut,
		Extra: []string{
			"--disable", "layer", "--disable", "evidence",
			"--no-network",
		},
	})
	_ = signRes

	if _, err := os.Stat(sigOut); err != nil {
		t.Fatalf("signature file %s was not produced: %v", sigOut, err)
	}

	verifyRes := helpers.RunVerify(t,
		"--sbom", bomOut,
		"--signature", sigOut,
		"--key", pubPath,
	)
	if verifyRes.ExitCode != 0 {
		t.Fatalf("verify failed (exit %d)\nstdout:\n%s\nstderr:\n%s",
			verifyRes.ExitCode, verifyRes.Stdout, verifyRes.Stderr)
	}
}

// requireCosignOnPath skips when cosign isn't available — the
// roundtrip test needs the real binary; mock-cosign tests live in
// the unit suite.
func requireCosignOnPath(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not on PATH — skipping signing roundtrip")
	}
}

// generateCosignKeyPair runs `cosign generate-key-pair` in dir with
// COSIGN_PASSWORD="" so the key has no passphrase. Returns paths to
// the private + public keys.
func generateCosignKeyPair(t *testing.T, dir string) (priv, pub string) {
	t.Helper()
	helpers.SetEnv(t, "COSIGN_PASSWORD", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cosign", "generate-key-pair")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair: %v\noutput:\n%s", err, out)
	}
	return filepath.Join(dir, "cosign.key"), filepath.Join(dir, "cosign.pub")
}
