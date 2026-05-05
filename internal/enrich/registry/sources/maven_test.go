package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

func TestMaven_Fetch(t *testing.T) {
	const pomXML = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.14.0</version>
  <description>Apache Commons Lang</description>
  <url>https://commons.apache.org/proper/commons-lang/</url>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
  <organization>
    <name>The Apache Software Foundation</name>
    <url>https://www.apache.org/</url>
  </organization>
  <scm>
    <url>https://gitbox.apache.org/repos/asf?p=commons-lang.git</url>
  </scm>
  <issueManagement>
    <system>jira</system>
    <url>https://issues.apache.org/jira/browse/LANG</url>
  </issueManagement>
</project>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pomXML))
	}))
	defer server.Close()

	m := NewMaven(nil, server.Client()).WithUpstream(server.URL)
	meta, err := m.Fetch(context.Background(),
		cpe.PURL{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.14.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta == nil {
		t.Fatal("nil meta")
	}
	if len(meta.Licenses) != 1 || meta.Licenses[0].SPDXID != "Apache-2.0" {
		t.Errorf("licenses = %+v", meta.Licenses)
	}
	if meta.Supplier.Name != "The Apache Software Foundation" {
		t.Errorf("supplier = %q", meta.Supplier.Name)
	}
	if meta.Homepage != "https://commons.apache.org/proper/commons-lang/" {
		t.Errorf("homepage = %q", meta.Homepage)
	}
	if meta.Repository != "https://gitbox.apache.org/repos/asf?p=commons-lang.git" {
		t.Errorf("repository = %q", meta.Repository)
	}
	if meta.BugTracker != "https://issues.apache.org/jira/browse/LANG" {
		t.Errorf("bug tracker = %q", meta.BugTracker)
	}
}

func TestMavenLicenseToSPDX(t *testing.T) {
	cases := map[string]string{
		"Apache License, Version 2.0": "Apache-2.0",
		"Apache 2":                    "Apache-2.0",
		"MIT License":                 "MIT",
		"MIT":                         "MIT",
		"BSD 3-Clause License":        "BSD-3-Clause",
		"Eclipse Public License 2.0":  "EPL-2.0",
		"GNU Lesser General Public License, Version 2.1": "LGPL-2.1-only",
		"Custom Internal License":                        "",
	}
	for in, want := range cases {
		if got := mavenLicenseToSPDX(in); got != want {
			t.Errorf("mavenLicenseToSPDX(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaven_FetchMissingFieldsUnsupported(t *testing.T) {
	m := NewMaven(nil, nil)
	_, err := m.Fetch(context.Background(), cpe.PURL{Type: "maven", Name: "x", Version: "1"})
	if err == nil {
		t.Error("expected error when groupId (Namespace) missing")
	}
}
