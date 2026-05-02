package fingerprint

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// JARMetadata is the relevant subset of a JAR's META-INF/MANIFEST.MF
// for SBOM purposes. All fields optional — JARs are wildly
// inconsistent about which keys they populate.
type JARMetadata struct {
	// BundleSymbolicName is the OSGi identifier ("org.apache.commons.lang3").
	BundleSymbolicName string
	// BundleName is the OSGi human name ("Apache Commons Lang 3").
	BundleName string
	// BundleVersion is the OSGi version.
	BundleVersion string
	// ImplementationTitle is the maven-style title.
	ImplementationTitle string
	// ImplementationVersion is the maven-style version.
	ImplementationVersion string
	// ImplementationVendor is the maven-style vendor.
	ImplementationVendor string
	// MainClass is the Java entrypoint, if any.
	MainClass string
}

// ReadJARMetadata reads MANIFEST.MF (and only the manifest) out of
// an in-memory JAR archive. body must point at the entire .jar/.war/
// .ear contents.
//
// Returns nil + ErrNotJAR when the input is not a zip with a
// MANIFEST.MF. Other zip / read errors are wrapped.
func ReadJARMetadata(body []byte) (*JARMetadata, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, ErrNotJAR
	}
	for _, f := range zr.File {
		if f.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("fingerprint: open MANIFEST.MF: %w", err)
		}
		defer func() { _ = rc.Close() }()

		body, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes))
		if err != nil {
			return nil, fmt.Errorf("fingerprint: read MANIFEST.MF: %w", err)
		}
		return parseManifest(body), nil
	}
	return nil, ErrNoManifest
}

// ErrNotJAR is returned when the input is not a zip archive.
var ErrNotJAR = fmt.Errorf("fingerprint: not a JAR/zip")

// ErrNoManifest is returned when the input IS a zip but lacks
// META-INF/MANIFEST.MF.
var ErrNoManifest = fmt.Errorf("fingerprint: no MANIFEST.MF")

// maxManifestBytes is a sanity cap — real manifests are KB-sized, a
// pathological one is fine to truncate.
const maxManifestBytes = 1 << 20 // 1 MiB

// parseManifest is the world's smallest java.util.jar.Manifest
// implementation. The format is "Key: value\r\n", with continuation
// lines starting with one space. We only care about a handful of
// keys, so anything else gets dropped on the floor.
func parseManifest(body []byte) *JARMetadata {
	out := &JARMetadata{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var lastKey, lastVal string
	commit := func() {
		if lastKey == "" {
			return
		}
		switch lastKey {
		case "Bundle-SymbolicName":
			out.BundleSymbolicName = strings.TrimSpace(strings.SplitN(lastVal, ";", 2)[0])
		case "Bundle-Name":
			out.BundleName = lastVal
		case "Bundle-Version":
			out.BundleVersion = lastVal
		case "Implementation-Title":
			out.ImplementationTitle = lastVal
		case "Implementation-Version":
			out.ImplementationVersion = lastVal
		case "Implementation-Vendor":
			out.ImplementationVendor = lastVal
		case "Main-Class":
			out.MainClass = lastVal
		}
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			commit()
			lastKey, lastVal = "", ""
			continue
		}
		if strings.HasPrefix(line, " ") {
			lastVal += strings.TrimPrefix(line, " ")
			continue
		}
		commit()
		idx := strings.Index(line, ":")
		if idx < 0 {
			lastKey, lastVal = "", ""
			continue
		}
		lastKey = strings.TrimSpace(line[:idx])
		lastVal = strings.TrimSpace(line[idx+1:])
	}
	commit()
	return out
}

// IsZIPArchive reports whether the first bytes of b match the ZIP
// PK\x03\x04 magic. JARs / WARs / EARs are zip archives.
func IsZIPArchive(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 0x03 && b[3] == 0x04
}
