package extractor

// File is the input every Extractor sees: a canonical path plus the
// in-memory body. The path is read for filename-based fallbacks
// (Java JAR filename versioning) and for routing decisions
// (`*.dist-info/METADATA` → Python). Body is the actual bytes.
//
// File is a value type — copying is cheap (the Body slice header is
// shared).
type File struct {
	// Path is the canonical (slash-separated, no leading slash)
	// path of the file inside the image. Equal to
	// `layer.FileEntry.Path`.
	Path string

	// Body is the file's bytes, already read into memory. The
	// caller owns the slice lifetime; Extractors must not retain
	// it beyond their call.
	Body []byte
}
