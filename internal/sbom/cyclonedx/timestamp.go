package cyclonedx

import "time"

// timestampFormat is the format CycloneDX requires for the metadata
// timestamp (RFC 3339 with second precision, UTC). cyclonedx-go does
// not validate the field — we parse and re-emit explicitly so the wire
// always uses one canonical shape.
const timestampFormat = "2006-01-02T15:04:05Z"

// parseTimestamp accepts the formats we observe in real-world SBOMs
// (Syft, cdxgen, Trivy emit slight variations) and returns a UTC time.
func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		timestampFormat,
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &timeParseError{value: s}
}

type timeParseError struct{ value string }

func (e *timeParseError) Error() string { return "cyclonedx: unrecognised timestamp: " + e.value }
