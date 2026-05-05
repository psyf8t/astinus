package source

import (
	"net/http"
	"testing"

	"github.com/psyf8t/astinus/internal/image/auth"
)

func TestOptionsBuildersWire(t *testing.T) {
	tr := http.DefaultTransport
	cred := auth.NewEnvProvider()

	o := applyOptions([]Option{
		WithTransport(tr),
		WithCredentials(cred),
		WithPlatform("linux/arm64"),
		WithInsecure(true),
	})

	if o.Transport != tr {
		t.Error("WithTransport not wired")
	}
	if o.Credentials != cred {
		t.Error("WithCredentials not wired")
	}
	if o.Platform != "linux/arm64" {
		t.Errorf("Platform = %q", o.Platform)
	}
	if !o.Insecure {
		t.Error("Insecure should be true")
	}
}

func TestApplyOptionsZero(t *testing.T) {
	o := applyOptions(nil)
	if o.Transport != nil || o.Credentials != nil || o.Platform != "" || o.Insecure {
		t.Errorf("zero Options has unexpected values: %+v", o)
	}
}
