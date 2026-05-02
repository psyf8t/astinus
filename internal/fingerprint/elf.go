package fingerprint

import "bytes"

// elfMagic is the four bytes that start every ELF binary.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// IsELF reports whether b begins with an ELF magic number. Pass at
// least 4 bytes — fewer always returns false.
func IsELF(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], elfMagic)
}

// peMagic is the two bytes ("MZ") that start PE/Windows binaries.
var peMagic = []byte{'M', 'Z'}

// IsPE reports whether b begins with the PE/Windows DOS-stub magic.
// Stage 4 only uses this for classification (so PE files end up as
// "executable" rather than "data"); structural extraction lives in a
// future stage.
func IsPE(b []byte) bool {
	return len(b) >= 2 && bytes.Equal(b[:2], peMagic)
}

// IsMachO reports whether b begins with one of the four Mach-O magic
// numbers (32-bit, 64-bit, big-endian variants). Same scope as IsPE
// — classification only for now.
func IsMachO(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && (b[3] == 0xce || b[3] == 0xcf):
		return true
	case b[0] == 0xce && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return true
	case b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return true
	}
	return false
}

// IsScriptShebang reports whether b begins with `#!`. Shebang scripts
// are recognised as "script" rather than "data" so they show up in
// the SBOM by name even when no metadata extraction is possible.
func IsScriptShebang(b []byte) bool {
	return len(b) >= 2 && b[0] == '#' && b[1] == '!'
}
