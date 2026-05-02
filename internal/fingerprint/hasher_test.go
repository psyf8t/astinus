package fingerprint

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestHasherSHA256Default(t *testing.T) {
	body := []byte("astinus")
	got, n, err := Hasher{}.Hash(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n = %d, want %d", n, len(body))
	}
	if len(got) != 1 || got[0].Algorithm != model.HashAlgorithmSHA256 {
		t.Fatalf("hashes = %+v", got)
	}
	// SHA-256 hex is 64 chars and deterministic.
	if len(got[0].Value) != 64 {
		t.Errorf("sha256 hex len = %d, want 64", len(got[0].Value))
	}
	// Cross-check by re-hashing — must be stable across calls.
	again, _, _ := Hasher{}.Hash(bytes.NewReader(body))
	if again[0].Value != got[0].Value {
		t.Errorf("sha256 not stable across calls")
	}
}

func TestHasherWithSHA1AndSHA512(t *testing.T) {
	body := []byte("astinus")
	got, _, err := Hasher{WithSHA1: true, WithSHA512: true}.Hash(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("hashes = %+v", got)
	}
	algs := map[string]bool{}
	for _, h := range got {
		algs[h.Algorithm] = true
	}
	for _, want := range []string{model.HashAlgorithmSHA256, model.HashAlgorithmSHA1, model.HashAlgorithmSHA512} {
		if !algs[want] {
			t.Errorf("missing %q in algs %v", want, algs)
		}
	}
}

func TestHashSHA256Helper(t *testing.T) {
	hex, n, err := HashSHA256(strings.NewReader("astinus"))
	if err != nil {
		t.Fatalf("HashSHA256: %v", err)
	}
	if n != 7 {
		t.Errorf("n = %d", n)
	}
	if len(hex) != 64 {
		t.Errorf("hex len = %d, want 64", len(hex))
	}
}
