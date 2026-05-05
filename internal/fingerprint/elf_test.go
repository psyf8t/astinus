package fingerprint

import "testing"

func TestIsELF(t *testing.T) {
	if !IsELF([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}) {
		t.Error("IsELF should match leading magic")
	}
	if IsELF([]byte{0x7f, 'E', 'L'}) {
		t.Error("IsELF needs 4 bytes")
	}
	if IsELF(nil) {
		t.Error("IsELF nil should be false")
	}
	if IsELF([]byte("hello")) {
		t.Error("IsELF unrelated bytes should be false")
	}
}

func TestIsPE(t *testing.T) {
	if !IsPE([]byte{'M', 'Z', 0x90}) {
		t.Error("IsPE should match")
	}
	if IsPE([]byte{'M'}) {
		t.Error("IsPE needs 2 bytes")
	}
	if IsPE([]byte{'P', 'K'}) {
		t.Error("IsPE rejects ZIP")
	}
}

func TestIsMachO(t *testing.T) {
	cases := [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, // 32-bit BE
		{0xfe, 0xed, 0xfa, 0xcf}, // 64-bit BE
		{0xce, 0xfa, 0xed, 0xfe}, // 32-bit LE
		{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit LE
	}
	for _, c := range cases {
		if !IsMachO(c) {
			t.Errorf("IsMachO(%x) should be true", c)
		}
	}
	if IsMachO([]byte{0x00, 0x00, 0x00, 0x00}) {
		t.Error("IsMachO unrelated bytes should be false")
	}
	if IsMachO([]byte{0xfe, 0xed}) {
		t.Error("IsMachO short input should be false")
	}
}

func TestIsScriptShebang(t *testing.T) {
	if !IsScriptShebang([]byte("#!/bin/sh")) {
		t.Error("IsScriptShebang should match")
	}
	if IsScriptShebang([]byte("# comment")) {
		t.Error("IsScriptShebang rejects bare hash")
	}
	if IsScriptShebang([]byte{}) {
		t.Error("IsScriptShebang empty should be false")
	}
}
