package sign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeMockCosign writes a small POSIX shell script that mimics
// cosign for the duration of one test. The script writes the
// supplied body to a side-channel file at MOCK_COSIGN_LOG and
// exits 0 unless MOCK_COSIGN_FAIL is set.
//
// Returns (cosignPath, logPath). The test inspects logPath after
// the run to assert which args / env cosign saw.
//
// Skipped on Windows where /bin/sh isn't guaranteed.
func writeMockCosign(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mock cosign uses /bin/sh; skipping on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mock-cosign.log")
	scriptPath := filepath.Join(dir, "cosign")
	script := `#!/bin/sh
# Mock cosign for astinus tests. Records args + env to MOCK_COSIGN_LOG.
{
    echo "ARGS: $*"
    echo "REKOR=$COSIGN_REKOR_URL"
    echo "FULCIO=$COSIGN_FULCIO_URL"
    echo "TUF=$TUF_ROOT"
    echo "SSL_CERT_FILE=$SSL_CERT_FILE"
    echo "PASSWORD_SET=$( [ -n "$COSIGN_PASSWORD" ] && echo yes || echo no )"
} > "$MOCK_COSIGN_LOG"
if [ -n "$MOCK_COSIGN_FAIL" ]; then
    echo "mock cosign: simulated failure" >&2
    exit 1
fi
echo "mock-cosign-bundle"
exit 0
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil { //nolint:gosec // test-only mock binary needs +x
		t.Fatalf("write mock cosign: %v", err)
	}
	t.Setenv("MOCK_COSIGN_LOG", logPath)
	return scriptPath, logPath
}

// readMockLog returns the recorded args / env entries the mock
// cosign script wrote during the test.
func readMockLog(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // test-only inspection of the mock cosign log
	if err != nil {
		t.Fatalf("read mock cosign log: %v", err)
	}
	return string(body)
}

func TestCosignSigner_NewErrToolingWhenMissing(t *testing.T) {
	_, err := NewCosignSigner(CosignOptions{CosignPath: "/no/such/cosign-binary"})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !errors.Is(err, ErrTooling) {
		t.Errorf("err = %v, want wraps ErrTooling", err)
	}
}

// TestCosignSigner_SignBlobBuildsCorrectArgs — drives the signer
// through the mock cosign and asserts the argv shape:
// `sign-blob --output-signature <out> --key <key> --yes <sbom>`.
func TestCosignSigner_SignBlobBuildsCorrectArgs(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatalf("NewCosignSigner: %v", err)
	}
	outDir := t.TempDir()
	sigPath := filepath.Join(outDir, "sbom.sig")
	keyPath := filepath.Join(outDir, "cosign.key")

	_, err = s.Sign(context.Background(), []byte(`{"bomFormat":"CycloneDX"}`), SignOptions{
		Format:     "cyclonedx",
		OutputFile: sigPath,
		KeyPath:    keyPath,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	log := readMockLog(t, logPath)
	for _, want := range []string{
		"sign-blob",
		"--output-signature " + sigPath,
		"--key " + keyPath,
		"--yes",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("argv missing %q\nfull log:\n%s", want, log)
		}
	}
}

// TestCosignSigner_AttestPredicateBuildsCorrectArgs — image-attached
// path: `attest --predicate <sbom> --type cyclonedx --key <k> --yes <ref>`.
func TestCosignSigner_AttestPredicateBuildsCorrectArgs(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "cosign.key")
	_, err = s.Sign(context.Background(), []byte(`{}`), SignOptions{
		Format:        "cyclonedx",
		AttachToImage: "ghcr.io/test/img:v1",
		KeyPath:       keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	log := readMockLog(t, logPath)
	for _, want := range []string{
		"attest",
		"--predicate ",
		"--type cyclonedx",
		"--key " + keyPath,
		"--yes ghcr.io/test/img:v1",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("argv missing %q\nfull log:\n%s", want, log)
		}
	}
}

// TestCosignSigner_KeylessOmitsKey — keyless mode (no KeyPath)
// must NOT pass `--key` to cosign.
func TestCosignSigner_KeylessOmitsKey(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Sign(context.Background(), []byte(`{}`), SignOptions{
		Format:        "cyclonedx",
		AttachToImage: "ghcr.io/test/img:v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	log := readMockLog(t, logPath)
	if strings.Contains(log, "--key") {
		t.Errorf("keyless mode passed --key:\n%s", log)
	}
	if !strings.Contains(log, "--yes ghcr.io/test/img:v1") {
		t.Errorf("missing --yes <image>:\n%s", log)
	}
}

// TestCosignSigner_CorporateSigstoreEnvVars — Rekor / Fulcio /
// TUF mirror URLs reach cosign through env vars.
func TestCosignSigner_CorporateSigstoreEnvVars(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "cosign.key")
	_, err = s.Sign(context.Background(), []byte(`{}`), SignOptions{
		Format:     "cyclonedx",
		KeyPath:    keyPath,
		OutputFile: filepath.Join(t.TempDir(), "sbom.sig"),
		RekorURL:   "https://rekor.corp/api/v1",
		FulcioURL:  "https://fulcio.corp",
		TUFMirror:  "https://tuf.corp",
		CABundle:   "/etc/ssl/corp-ca.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	log := readMockLog(t, logPath)
	for _, want := range []string{
		"REKOR=https://rekor.corp/api/v1",
		"FULCIO=https://fulcio.corp",
		"TUF=https://tuf.corp",
		"SSL_CERT_FILE=/etc/ssl/corp-ca.pem",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("env var missing %q\nfull log:\n%s", want, log)
		}
	}
}

// TestCosignSigner_KeyPasswordEnvForwarded — the operator's
// custom-named password env var lands as COSIGN_PASSWORD when
// cosign runs.
func TestCosignSigner_KeyPasswordEnvForwarded(t *testing.T) {
	mockPath, logPath := writeMockCosign(t)
	t.Setenv("MY_KEY_PW", "supersecret123")
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Sign(context.Background(), []byte(`{}`), SignOptions{
		Format:         "cyclonedx",
		KeyPath:        filepath.Join(t.TempDir(), "k"),
		OutputFile:     filepath.Join(t.TempDir(), "s"),
		KeyPasswordEnv: "MY_KEY_PW",
	})
	if err != nil {
		t.Fatal(err)
	}
	log := readMockLog(t, logPath)
	if !strings.Contains(log, "PASSWORD_SET=yes") {
		t.Errorf("COSIGN_PASSWORD not forwarded:\n%s", log)
	}
}

// TestCosignSigner_FailingCosignReturnsErrSigning — non-zero exit
// from cosign maps to ErrSigning with the stderr preserved.
func TestCosignSigner_FailingCosignReturnsErrSigning(t *testing.T) {
	mockPath, _ := writeMockCosign(t)
	t.Setenv("MOCK_COSIGN_FAIL", "1")
	s, err := NewCosignSigner(CosignOptions{CosignPath: mockPath})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Sign(context.Background(), []byte(`{}`), SignOptions{
		Format:     "cyclonedx",
		KeyPath:    filepath.Join(t.TempDir(), "k"),
		OutputFile: filepath.Join(t.TempDir(), "s"),
	})
	if err == nil {
		t.Fatal("expected error from failing cosign")
	}
	if !errors.Is(err, ErrSigning) {
		t.Errorf("err = %v, want wraps ErrSigning", err)
	}
	if !strings.Contains(err.Error(), "simulated failure") {
		t.Errorf("err missing stderr tail: %v", err)
	}
}

// TestSignOptionsValidate — fail-fast on misconfigured opts before
// we ever fork cosign.
func TestSignOptionsValidate(t *testing.T) {
	cases := []struct {
		name string
		mode Mode
		opts SignOptions
		want bool // true = expect error
	}{
		{"none always ok", ModeNone, SignOptions{}, false},
		{"key without path", ModeCosignKey,
			SignOptions{OutputFile: "/tmp/s"}, true},
		{"key with path + output", ModeCosignKey,
			SignOptions{KeyPath: "/k", OutputFile: "/tmp/s"}, false},
		{"key with path + image", ModeCosignKey,
			SignOptions{KeyPath: "/k", AttachToImage: "img:v1"}, false},
		{"key with path but no destination", ModeCosignKey,
			SignOptions{KeyPath: "/k"}, true},
		{"keyless no destination", ModeCosignKeyless,
			SignOptions{}, true},
		{"keyless with image", ModeCosignKeyless,
			SignOptions{AttachToImage: "img:v1"}, false},
		{"unknown mode", Mode("garbage"),
			SignOptions{OutputFile: "/tmp/s"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.opts.Validate(c.mode)
			if (err != nil) != c.want {
				t.Errorf("Validate err = %v, want err? %v", err, c.want)
			}
		})
	}
}

// TestMaskSensitive — key paths and tokens are redacted in log
// fields.
func TestMaskSensitive(t *testing.T) {
	cases := []struct {
		args        []string
		mustHave    []string
		mustNotHave []string
	}{
		{
			args:        []string{"sign-blob", "--key", "/path/to/secret.key", "--yes", "/tmp/sbom"},
			mustHave:    []string{"--key", "<redacted>"},
			mustNotHave: []string{"/path/to/secret.key"},
		},
		{
			args:        []string{"verify-blob", "--cert", "/tmp/cert.pem", "/tmp/sbom"},
			mustHave:    []string{"--cert", "<redacted>"},
			mustNotHave: []string{"/tmp/cert.pem"},
		},
	}
	for _, c := range cases {
		got := strings.Join(maskSensitive(c.args), " ")
		for _, want := range c.mustHave {
			if !strings.Contains(got, want) {
				t.Errorf("got %q, want contains %q", got, want)
			}
		}
		for _, forbidden := range c.mustNotHave {
			if strings.Contains(got, forbidden) {
				t.Errorf("got %q, must not contain %q", got, forbidden)
			}
		}
	}
}

func TestModeIsKnown(t *testing.T) {
	cases := map[Mode]bool{
		ModeNone:          true,
		ModeCosignKey:     true,
		ModeCosignKeyless: true,
		Mode("nope"):      false,
	}
	for m, want := range cases {
		if m.IsKnown() != want {
			t.Errorf("Mode(%q).IsKnown = %v, want %v", string(m), m.IsKnown(), want)
		}
	}
}

func TestModeForOptions(t *testing.T) {
	if got := ModeForOptions(SignOptions{KeyPath: "/k"}); got != ModeCosignKey {
		t.Errorf("with KeyPath = %q, want cosign-key", got)
	}
	if got := ModeForOptions(SignOptions{}); got != ModeCosignKeyless {
		t.Errorf("without KeyPath = %q, want cosign-keyless", got)
	}
}

func TestAttestationTypeFor(t *testing.T) {
	cases := map[string]string{
		"cyclonedx":      "cyclonedx",
		"CycloneDX-JSON": "cyclonedx",
		"spdx":           "spdxjson",
		"SPDX-JSON":      "spdxjson",
		"sarif":          "custom",
		"":               "custom",
	}
	for in, want := range cases {
		if got := attestationTypeFor(in); got != want {
			t.Errorf("attestationTypeFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPredicateURIFor(t *testing.T) {
	cases := map[string]string{
		"cyclonedx": "https://cyclonedx.org/bom/v1.6",
		"spdx-json": "https://spdx.dev/Document",
		"unknown":   "",
	}
	for in, want := range cases {
		if got := predicateURIFor(in); got != want {
			t.Errorf("predicateURIFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLastStderrLines(t *testing.T) {
	in := "first\nsecond\nthird\nfourth\n"
	got := lastStderrLines(in, 2)
	if got != "third\nfourth" {
		t.Errorf("got %q, want last 2 lines", got)
	}
	if got := lastStderrLines("", 3); got != "" {
		t.Errorf("empty input should return empty, got %q", got)
	}
}
