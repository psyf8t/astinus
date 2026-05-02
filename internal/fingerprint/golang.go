package fingerprint

import (
	"debug/buildinfo"
	"fmt"
	"io"
	"runtime/debug"
)

// GoModule is one entry from a Go binary's embedded build info.
type GoModule struct {
	// Path is the import path of the module ("github.com/psyf8t/astinus").
	Path string
	// Version is the module version ("v1.2.3" or "(devel)").
	Version string
	// Sum is the module sum if recorded ("h1:...").
	Sum string
	// Replace, if non-nil, points to the replacing module.
	Replace *GoModule
}

// GoBuildInfo summarises a Go binary's embedded build info.
type GoBuildInfo struct {
	// GoVersion is the toolchain version that built the binary
	// ("go1.25").
	GoVersion string
	// Path is the main module's import path.
	Path string
	// Main is the main module entry.
	Main GoModule
	// Deps is every direct/indirect dependency the binary linked.
	Deps []GoModule
}

// readerAtSeeker is the union type debug/buildinfo accepts.
type readerAtSeeker interface {
	io.ReaderAt
}

// ReadGoBuildInfo parses a Go binary's embedded build info.
//
// The reader must support io.ReaderAt (a *bytes.Reader or *os.File
// will do). Returns nil + a wrapped error when the input is not a
// Go binary or the build info section is missing/corrupt.
func ReadGoBuildInfo(r readerAtSeeker) (*GoBuildInfo, error) {
	bi, err := buildinfo.Read(r)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: read go buildinfo: %w", err)
	}

	info := &GoBuildInfo{
		GoVersion: bi.GoVersion,
		Path:      bi.Path,
		Main:      goModuleFrom(bi.Main),
	}
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		info.Deps = append(info.Deps, goModuleFrom(*d))
	}
	return info, nil
}

// goModuleFrom converts the stdlib's debug.Module into our GoModule.
// nil-tolerant for the recursive Replace pointer.
func goModuleFrom(m debug.Module) GoModule {
	out := GoModule{Path: m.Path, Version: m.Version, Sum: m.Sum}
	if m.Replace != nil {
		repl := goModuleFrom(*m.Replace)
		out.Replace = &repl
	}
	return out
}
