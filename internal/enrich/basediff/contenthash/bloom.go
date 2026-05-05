package contenthash

import (
	"encoding/binary"
	"encoding/hex"
	"math"
)

// bloom is a simple Bloom filter sized for an expected item count
// and a target false-positive rate.
//
// Inputs are SHA-256 hex strings (64 ASCII bytes); we read 16 bytes
// of entropy from the first 32 hex characters and synthesise k hash
// functions via the Kirsch-Mitzenmacher "double hashing" trick:
//
//	hash_i(x) = (h1(x) + i * h2(x)) mod m
//
// SHA-256 is itself a strong hash, so reusing two of its 64-bit
// chunks as h1 / h2 is statistically indistinguishable from running
// two independent hash functions over the input.
type bloom struct {
	bits    []uint64 // bit array, LSB-first within each word
	nBits   uint64
	nHashes int
}

// newBloom returns a Bloom filter sized for expectedItems with the
// given target false-positive rate. fpRate must be in (0, 1).
//
// Capacity formula:
//
//	m = -n * ln(p) / (ln 2)^2
//	k = (m / n) * ln 2
//
// For n=10 000, p=0.01 the result is m ≈ 95 851 bits, k ≈ 7 hash
// functions — the classical 1 % FP rate config for a 10 k filter.
func newBloom(expectedItems int, fpRate float64) *bloom {
	if expectedItems < 1 {
		expectedItems = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}
	mFloat := -float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)
	m := uint64(math.Ceil(mFloat))
	if m < 64 {
		m = 64
	}
	kFloat := math.Ceil(mFloat / float64(expectedItems) * math.Ln2)
	k := int(kFloat)
	if k < 1 {
		k = 1
	}
	return &bloom{
		bits:    make([]uint64, (m+63)/64),
		nBits:   m,
		nHashes: k,
	}
}

// add records sha256Hex (a 64-char SHA-256 hex string) as present.
// Strings shorter than 32 hex characters fall back to padding-zeros
// behaviour — they still hash deterministically but lose entropy.
func (b *bloom) add(sha256Hex string) {
	h1, h2 := bloomHashes(sha256Hex)
	for i := 0; i < b.nHashes; i++ {
		idx := (h1 + uint64(i)*h2) % b.nBits
		b.bits[idx/64] |= 1 << (idx % 64)
	}
}

// test reports whether sha256Hex MAY be present. False positives are
// possible at the configured rate; false negatives are impossible.
func (b *bloom) test(sha256Hex string) bool {
	h1, h2 := bloomHashes(sha256Hex)
	for i := 0; i < b.nHashes; i++ {
		idx := (h1 + uint64(i)*h2) % b.nBits
		if b.bits[idx/64]&(1<<(idx%64)) == 0 {
			return false
		}
	}
	return true
}

// bloomHashes returns two 64-bit values derived from the first 32
// hex characters of s. When s is shorter, missing bytes are zeros
// (acceptable for short hex strings used in tests; production paths
// always pass the full 64-char SHA-256).
func bloomHashes(s string) (uint64, uint64) {
	var raw [16]byte
	if len(s) >= 32 {
		_, _ = hex.Decode(raw[:], []byte(s[:32]))
	} else {
		_, _ = hex.Decode(raw[:len(s)/2], []byte(s[:len(s)&^1]))
	}
	h1 := binary.BigEndian.Uint64(raw[0:8])
	h2 := binary.BigEndian.Uint64(raw[8:16])
	// h2==0 would collapse the synthesised hash sequence to a single
	// repeated index. Statistically rare, but trivial to repair.
	if h2 == 0 {
		h2 = 1
	}
	return h1, h2
}
