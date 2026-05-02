package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestKnownIncludesBuiltins(t *testing.T) {
	known := Known()
	for _, want := range []string{FormatCycloneDXJSON, FormatCycloneDXXML} {
		found := false
		for _, k := range known {
			if k == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Known() does not contain %q (got %v)", want, known)
		}
	}
}

func TestGetUnknownFormat(t *testing.T) {
	if _, err := Get("not-a-real-format", Options{}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestCycloneDXJSONRendererProducesValidJSON(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "x", Version: "1", Type: model.ComponentTypeLibrary},
		},
	}
	r, err := Get(FormatCycloneDXJSON, Options{Pretty: true})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Name() != FormatCycloneDXJSON {
		t.Errorf("Name = %q", r.Name())
	}
	if r.MIMEType() == "" {
		t.Error("MIMEType should be non-empty")
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, sbom); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(buf.Bytes(), &probe); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if probe["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", probe["bomFormat"])
	}
}

func TestCycloneDXXMLRendererProducesXML(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{Name: "x", Version: "1"}}}
	r, err := Get(FormatCycloneDXXML, Options{Pretty: false})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, sbom); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("<bom")) {
		t.Errorf("output does not look like XML: %q", buf.String())
	}
}

func TestResolveSame(t *testing.T) {
	cases := map[model.Format]string{
		model.FormatCycloneDXJSON: FormatCycloneDXJSON,
		model.FormatCycloneDXXML:  FormatCycloneDXXML,
		model.FormatSPDXJSON:      FormatSPDXJSON,
		model.FormatSPDXTagValue:  FormatSPDXTagValue,
		model.FormatUnknown:       FormatCycloneDXJSON,
	}
	for in, want := range cases {
		if got := ResolveSame(in); got != want {
			t.Errorf("ResolveSame(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenStdoutIsNopClose(t *testing.T) {
	w, err := Open(StdoutPath)
	if err != nil {
		t.Fatalf("Open(-): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close stdout wrapper: %v", err)
	}
}

func TestOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open file: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("file content = %q", string(body))
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestOpenUnwritableDirectory(t *testing.T) {
	_, err := Open("/no/such/dir/out.json")
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
	if !errors.Is(err, fs.ErrNotExist) && !bytes.Contains([]byte(err.Error()), []byte("/no/such/dir")) {
		t.Errorf("error = %v", err)
	}
}

func TestRegisterFormatDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	RegisterFormat(FormatCycloneDXJSON, func(Options) Renderer { return nil })
}
