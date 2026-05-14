package layer

import (
	"bufio"
	"io"
	"strings"
)

// dpkgStatusPath is the canonical filesystem location of the dpkg
// status file that tracks every installed package on Debian / Ubuntu
// systems. Stored as a normalised path (no leading `/`) to match the
// FileMap key convention. S7 Task 3 / ADR-0060 amendment.
const dpkgStatusPath = "var/lib/dpkg/status"

// DpkgStatusPath is the exported variant so cross-package callers
// (basediff's metadata-path filter) reference the same string.
const DpkgStatusPath = dpkgStatusPath

// dpkgRecord is one parsed entry from `/var/lib/dpkg/status`. Only
// the two fields the earliest-layer lookup needs are captured — the
// real dpkg-status schema has 20+ keys per record (Package: Status:
// Priority: Section: Source: Version: Installed-Size: Maintainer:
// Architecture: Multi-Arch: Depends: …), but Astinus only resolves
// against (name, version) so the rest is ignored.
type dpkgRecord struct {
	Name    string
	Version string
}

// parseDpkgStatus streams r (an unzipped `/var/lib/dpkg/status`
// body) and returns the records it carries. Format: RFC822-style
// `Key: value` lines, records separated by a blank line; multi-
// line continuation values use leading space (we read those as
// part of the same key's value but only Package: + Version:
// matter for the earliest-layer use case). The parser is forgiving
// — a malformed record is skipped rather than erroring out, since
// downstream callers only need a best-effort (name, version) index
// and the dpkg-status file is human-edited on rare occasions.
// S7 Task 3 / ADR-0060 amendment.
func parseDpkgStatus(r io.Reader) []dpkgRecord {
	if r == nil {
		return nil
	}
	scanner := bufio.NewScanner(r)
	// dpkg-status records are short (rarely > 4 KiB even with long
	// Description: blocks); 1 MiB max guards against pathological
	// input without paying the default 64 KiB buffer's overhead on
	// the small case.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []dpkgRecord
	var cur dpkgRecord
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = dpkgRecord{}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		// Multi-line continuation (leading space) — skip; we only
		// care about Package: and Version: which are always
		// single-line.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		key, value, ok := splitDpkgLine(line)
		if !ok {
			continue
		}
		switch key {
		case "Package":
			cur.Name = value
		case "Version":
			cur.Version = value
		}
	}
	// Final record may not be terminated with a blank line.
	flush()
	return out
}

// splitDpkgLine splits a `Key: value` line into (key, value, true).
// Returns ("", "", false) when the line doesn't follow the format
// (no colon, or colon at index 0).
func splitDpkgLine(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	key := line[:idx]
	value := line[idx+1:]
	// Strip a single leading space after the colon (RFC822 says it
	// SHOULD be there but doesn't require it). Don't trim further
	// — dpkg version values can have meaningful trailing chars.
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return key, value, true
}

// dpkgRecordKey returns the canonical lookup key used by the
// FileMap's dpkgEarliest index. Format `name@version`. Matches the
// apkRecordKey shape so a future generic earliest-package lookup
// API can fold the two indices into one. S7 Task 3.
func dpkgRecordKey(name, version string) string {
	if name == "" {
		return ""
	}
	return strings.TrimRight(name+"@"+version, "@")
}
