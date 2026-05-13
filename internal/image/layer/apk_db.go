package layer

import (
	"bufio"
	"io"
	"strings"
)

// apkInstalledPath is the canonical filesystem location of the apk
// "installed" database that records every package + version present
// on an Alpine system. Stored as a normalised path (no leading `/`)
// to match the FileMap key convention.
const apkInstalledPath = "lib/apk/db/installed"

// ApkInstalledPath is the exported variant of the constant so other
// packages can reference the same path string without re-typing it.
// Public so tests in adjacent packages can construct fixture data.
const ApkInstalledPath = apkInstalledPath

// apkRecord is one parsed entry from `/lib/apk/db/installed`. Only
// the two fields the earliest-layer lookup needs are captured — the
// real apk DB schema has ~20 keys per record (C: P: V: A: S: I: T:
// U: L: o: m: t: c: F: M: R: D: r: …), but Astinus only resolves
// against (name, version) so the rest is ignored.
type apkRecord struct {
	Name    string
	Version string
}

// parseApkInstalled streams r (an unzipped `/lib/apk/db/installed`
// body) and returns the records it carries. Format: line-based
// `K:value`, records separated by a blank line; key letters of
// interest are `P:` (package name) and `V:` (version). The parser
// is forgiving — a malformed record is skipped rather than
// erroring out, since downstream callers only need a best-effort
// (name, version) index and the apk DB is human-edited on rare
// occasions. ADR-0059.
func parseApkInstalled(r io.Reader) []apkRecord {
	if r == nil {
		return nil
	}
	scanner := bufio.NewScanner(r)
	// apk DB lines are short (rarely > 200 bytes); 1 MiB max
	// guards against pathological input without paying the default
	// 64 KiB buffer's overhead on the small case.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []apkRecord
	var cur apkRecord
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = apkRecord{}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key, value := line[0], line[2:]
		switch key {
		case 'P':
			cur.Name = value
		case 'V':
			cur.Version = value
		}
	}
	// Final record may not be terminated with a blank line.
	flush()
	return out
}

// apkRecordKey returns the canonical lookup key used by the
// FileMap's apkEarliest index. Format `name@version`. The
// FileMap.ApkEarliestLayer caller passes the same shape so
// downstream code doesn't grow a tuple-keyed map.
func apkRecordKey(name, version string) string {
	if name == "" {
		return ""
	}
	// Match apk's display convention: name@version with no padding.
	// Version may be empty for partial fixtures; in that case the
	// key collapses to "name@", which still matches any apk row
	// the parser produced without a V: line.
	return strings.TrimRight(name+"@"+version, "@")
}
