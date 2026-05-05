package contenthash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
)

// ─── Bloom filter ────────────────────────────────────────────────────

func TestBloomNoFalseNegatives(t *testing.T) {
	b := newBloom(10_000, 0.01)
	added := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		h := hashOf("base-" + strconv.Itoa(i))
		b.add(h)
		added = append(added, h)
	}
	for _, h := range added {
		if !b.test(h) {
			t.Fatalf("bloom must never report false negative for %s", h)
		}
	}
}

func TestBloomFPRateUnder2Percent(t *testing.T) {
	const n = 10_000
	b := newBloom(n, 0.01)
	for i := 0; i < n; i++ {
		b.add(hashOf("present-" + strconv.Itoa(i)))
	}
	fp := 0
	for i := 0; i < n; i++ {
		if b.test(hashOf("missing-" + strconv.Itoa(i))) {
			fp++
		}
	}
	rate := float64(fp) / float64(n)
	t.Logf("bloom FP rate = %.4f over %d trials", rate, n)
	if rate > 0.02 {
		t.Errorf("FP rate = %.4f, want < 0.02 (1%% target + headroom)", rate)
	}
}

func TestBloomShortInputDoesNotPanic(t *testing.T) {
	b := newBloom(100, 0.01)
	// Production input is always 64 hex chars; the helper happens to
	// accept shorter strings (test fixtures, malformed input). Make
	// sure it doesn't panic on extremes.
	for _, s := range []string{"", "a", "ab", "abcd", "abcdef0123456789"} {
		b.add(s)
		_ = b.test(s)
	}
}

func TestBloomDefaultsOnInvalidInputs(t *testing.T) {
	// Zero items / out-of-range fpRate fall back to defensible
	// defaults rather than panicking.
	b := newBloom(0, 0)
	if b.nBits == 0 || b.nHashes == 0 {
		t.Errorf("bloom must populate defaults: nBits=%d nHashes=%d", b.nBits, b.nHashes)
	}
}

// ─── BaseSet ─────────────────────────────────────────────────────────

func TestBaseSetAddContains(t *testing.T) {
	s := NewBaseSet(100)
	h := hashOf("hello")
	s.Add(h, Evidence{BasePath: "usr/bin/hello", LayerIndex: 1, Size: 5})

	ev, ok := s.Contains(h)
	if !ok {
		t.Fatal("Contains should return true for added hash")
	}
	if ev.BasePath != "usr/bin/hello" || ev.LayerIndex != 1 || ev.Size != 5 {
		t.Errorf("evidence = %+v", ev)
	}
}

func TestBaseSetMissingHash(t *testing.T) {
	s := NewBaseSet(100)
	if _, ok := s.Contains(hashOf("nope")); ok {
		t.Error("Contains should return false for unknown hash")
	}
}

func TestBaseSetAddPreservesFirstEvidence(t *testing.T) {
	s := NewBaseSet(100)
	h := hashOf("dup")
	s.Add(h, Evidence{BasePath: "first/path", LayerIndex: 0, Size: 1})
	s.Add(h, Evidence{BasePath: "second/path", LayerIndex: 1, Size: 2})

	ev, _ := s.Contains(h)
	if ev.BasePath != "first/path" {
		t.Errorf("BasePath = %q, want first/path (first-write wins)", ev.BasePath)
	}
	// Both paths should still be discoverable via HasPath.
	if !s.HasPath("first/path") || !s.HasPath("second/path") {
		t.Error("HasPath should index every evidence path")
	}
	// Size counts distinct hashes, not paths.
	if s.Size() != 1 {
		t.Errorf("Size = %d, want 1", s.Size())
	}
	if s.PathCount() != 2 {
		t.Errorf("PathCount = %d, want 2", s.PathCount())
	}
}

func TestBaseSetHasPathOnUnknownPath(t *testing.T) {
	s := NewBaseSet(10)
	if s.HasPath("nope") {
		t.Error("HasPath should be false on a never-added path")
	}
}

func TestBaseSetSizeAndPathCountStartZero(t *testing.T) {
	s := NewBaseSet(10)
	if s.Size() != 0 || s.PathCount() != 0 {
		t.Errorf("empty BaseSet: Size=%d PathCount=%d", s.Size(), s.PathCount())
	}
}

func TestBaseSetEndToEndFPRate(t *testing.T) {
	const n = 10_000
	s := NewBaseSet(n)
	for i := 0; i < n; i++ {
		s.Add(hashOf(fmt.Sprintf("base-%d", i)), Evidence{
			BasePath: fmt.Sprintf("usr/lib/file-%d", i), LayerIndex: 0, Size: 1,
		})
	}
	// Real FP would be detected as "Contains true" + "exact map miss";
	// our Contains short-circuits on the bloom test BEFORE the map
	// lookup, so a true FP is one where bloom says yes but exact says
	// no. Count that.
	fp := 0
	for i := 0; i < n; i++ {
		h := hashOf(fmt.Sprintf("missing-%d", i))
		if !s.bloom.test(h) {
			continue // bloom correctly rejected
		}
		if _, exact := s.exact[h]; !exact {
			fp++
		}
	}
	rate := float64(fp) / float64(n)
	t.Logf("BaseSet end-to-end bloom FP rate = %.4f", rate)
	if rate > 0.02 {
		t.Errorf("FP rate = %.4f, want < 0.02", rate)
	}
}

// hashOf returns a SHA-256 hex string of s. Used to fabricate
// realistic-shaped hash inputs without typing 64 hex chars by hand.
func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
