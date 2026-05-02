package fingerprint

import (
	"bytes"
	"testing"
)

// FuzzReadGoBuildInfo asserts the Go buildinfo reader cannot panic
// on arbitrary byte input. Seeded with empty / near-empty bytes plus
// a few crafted shapes that look like ELF / Mach-O headers; the
// fuzzer mutates from there. The function under test takes an
// io.ReaderAt, so we wrap the input in *bytes.Reader.
//
// post-stage-13 review F-006. This parser had 0% coverage before
// this fuzz target.
func FuzzReadGoBuildInfo(f *testing.F) {
	for _, s := range [][]byte{
		nil,
		{},
		{0x00},
		// ELF magic: 0x7F E L F (64-bit, little-endian, current)
		{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00},
		// Mach-O 64-bit magic
		{0xCF, 0xFA, 0xED, 0xFE},
		// PE magic ("MZ")
		{0x4D, 0x5A},
		bytes.Repeat([]byte{0x00}, 1024),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap fuzz inputs to a sensible size so a runaway corpus
		// entry can't allocate gigabytes — the underlying
		// debug/buildinfo reader will read sections by offset.
		const max = 1 << 20 // 1 MiB
		if len(data) > max {
			t.Skip("fuzz input larger than 1 MiB")
		}
		// Contract: no panic, no infinite loop. Returning an error
		// is the expected outcome for almost every input.
		_, _ = ReadGoBuildInfo(bytes.NewReader(data))
	})
}
