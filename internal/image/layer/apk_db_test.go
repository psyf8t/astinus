package layer

import (
	"strings"
	"testing"
)

const sampleApkInstalled = `C:Q1abc
P:musl
V:1.2.5-r0
A:x86_64
S:1234

C:Q1def
P:busybox
V:1.36.1-r29
A:x86_64
S:5678

C:Q1ghi
P:curl
V:8.5.0-r0
A:x86_64
S:9999
`

func TestParseApkInstalled(t *testing.T) {
	got := parseApkInstalled(strings.NewReader(sampleApkInstalled))
	want := []apkRecord{
		{Name: "musl", Version: "1.2.5-r0"},
		{Name: "busybox", Version: "1.36.1-r29"},
		{Name: "curl", Version: "8.5.0-r0"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("record %d = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseApkInstalled_TrailingRecordWithoutBlankLine(t *testing.T) {
	// Real apk DBs often omit the trailing blank line — make sure
	// the parser still flushes the final record.
	body := `P:musl
V:1.2.5-r0`
	got := parseApkInstalled(strings.NewReader(body))
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0] != (apkRecord{Name: "musl", Version: "1.2.5-r0"}) {
		t.Errorf("record = %+v, want musl/1.2.5-r0", got[0])
	}
}

func TestParseApkInstalled_SkipsMalformedLines(t *testing.T) {
	body := `P:musl
this-line-has-no-colon
V:1.2.5
:value-with-no-key
P:another

`
	got := parseApkInstalled(strings.NewReader(body))
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (first block flushed; second has no V)", len(got))
	}
	if got[0].Name != "another" {
		// Implementation detail: the parser keeps writing into cur,
		// so the second `P:another` overwrites the prior name. The
		// behaviour is documented: malformed input is best-effort.
		// We pin "another" specifically because it's the most-recent
		// P: at flush time — any future change to the parser must
		// keep this contract or update both code + test together.
		t.Errorf("record = %+v, want name=another (best-effort P-wins)", got[0])
	}
}

func TestParseApkInstalled_EmptyInput(t *testing.T) {
	if got := parseApkInstalled(strings.NewReader("")); len(got) != 0 {
		t.Errorf("empty input → %d records, want 0", len(got))
	}
	if got := parseApkInstalled(nil); got != nil {
		t.Errorf("nil reader → %v, want nil", got)
	}
}

func TestApkRecordKey(t *testing.T) {
	cases := []struct{ name, ver, want string }{
		{"musl", "1.2.5-r0", "musl@1.2.5-r0"},
		{"busybox", "", "busybox"},
		{"", "1.0", ""},
	}
	for _, c := range cases {
		if got := apkRecordKey(c.name, c.ver); got != c.want {
			t.Errorf("apkRecordKey(%q, %q) = %q, want %q", c.name, c.ver, got, c.want)
		}
	}
}
