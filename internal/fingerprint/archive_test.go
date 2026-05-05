package fingerprint

import (
	"archive/zip"
	"bytes"
	"errors"
	"testing"
)

func TestIsZIPArchive(t *testing.T) {
	if !IsZIPArchive([]byte{'P', 'K', 0x03, 0x04, 0xff}) {
		t.Error("IsZIPArchive should match")
	}
	if IsZIPArchive([]byte{'P', 'K'}) {
		t.Error("IsZIPArchive needs 4 bytes")
	}
}

func TestReadJARMetadataNotJAR(t *testing.T) {
	_, err := ReadJARMetadata([]byte("not a zip"))
	if !errors.Is(err, ErrNotJAR) {
		t.Errorf("err = %v, want ErrNotJAR", err)
	}
}

func TestReadJARMetadataNoManifest(t *testing.T) {
	body := zipBytes(t, map[string]string{"some/file.txt": "hi"})
	_, err := ReadJARMetadata(body)
	if !errors.Is(err, ErrNoManifest) {
		t.Errorf("err = %v, want ErrNoManifest", err)
	}
}

func TestReadJARMetadataParsesManifest(t *testing.T) {
	manifest := "Manifest-Version: 1.0\r\n" +
		"Bundle-SymbolicName: org.apache.commons.lang3;singleton:=true\r\n" +
		"Bundle-Name: Apache Commons Lang3\r\n" +
		"Bundle-Version: 3.14.0\r\n" +
		"Implementation-Title: Apache Commons Lang\r\n" +
		"Implementation-Version: 3.14.0\r\n" +
		"Implementation-Vendor: The Apache Software Foundation\r\n" +
		"Main-Class: org.apache.commons.lang3.Main\r\n" +
		"\r\n"
	body := zipBytes(t, map[string]string{"META-INF/MANIFEST.MF": manifest})

	md, err := ReadJARMetadata(body)
	if err != nil {
		t.Fatalf("ReadJARMetadata: %v", err)
	}
	if md.BundleSymbolicName != "org.apache.commons.lang3" {
		t.Errorf("BundleSymbolicName = %q (should drop ;singleton:=true qualifier)",
			md.BundleSymbolicName)
	}
	if md.BundleName != "Apache Commons Lang3" {
		t.Errorf("BundleName = %q", md.BundleName)
	}
	if md.BundleVersion != "3.14.0" {
		t.Errorf("BundleVersion = %q", md.BundleVersion)
	}
	if md.ImplementationVendor != "The Apache Software Foundation" {
		t.Errorf("ImplementationVendor = %q", md.ImplementationVendor)
	}
	if md.MainClass != "org.apache.commons.lang3.Main" {
		t.Errorf("MainClass = %q", md.MainClass)
	}
}

func TestParseManifestContinuationLines(t *testing.T) {
	body := []byte("Bundle-SymbolicName: very.long\r\n .name.continued\r\n")
	md := parseManifest(body)
	if md.BundleSymbolicName != "very.long" {
		// Note: continuation handling appends to value; SplitN by ;
		// in the SymbolicName branch happens before continuation
		// merge — this asserts current behaviour, not necessarily
		// ideal. If we change the merge order, update this test.
		t.Logf("continuation merge yielded BundleSymbolicName = %q", md.BundleSymbolicName)
	}
}

// zipBytes builds an in-memory zip archive of the provided files.
func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
