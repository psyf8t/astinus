package registry

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
)

// applyAuth attaches Authorization / custom-header credentials to
// req per the mirror's auth config. Secrets are read from env vars
// at call time so a long-running process picks up rotated tokens
// without restart.
//
// Returns an error when the auth type is unknown or the configured
// credentials are empty (env var unset). Both are operator errors —
// failing loudly is better than silently sending unauthenticated
// requests against a mirror that requires auth.
func applyAuth(req *http.Request, auth *config.MirrorAuthConfig) error {
	if auth == nil {
		return nil
	}
	switch auth.Type {
	case "bearer":
		token := readSecret(auth.Token, auth.TokenEnv)
		if token == "" {
			return fmt.Errorf("registry auth: bearer token empty (token_env=%q)", auth.TokenEnv)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case "basic":
		password := readSecret(auth.Password, auth.PasswordEnv)
		if password == "" {
			return fmt.Errorf("registry auth: basic password empty (password_env=%q)", auth.PasswordEnv)
		}
		req.SetBasicAuth(auth.Username, password)
	case "header":
		value := readSecret(auth.HeaderValue, auth.HeaderValueEnv)
		if value == "" {
			return fmt.Errorf("registry auth: header value empty (header_value_env=%q)", auth.HeaderValueEnv)
		}
		req.Header.Set(auth.HeaderName, value)
	default:
		return fmt.Errorf("registry auth: unknown type %q (want bearer|basic|header)", auth.Type)
	}
	return nil
}

// applyHeaders attaches the per-mirror custom-header bag to req.
// Values may reference env vars via `${VAR}` expansion so corp YAML
// configs keep the literal secret out of the file.
func applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, expandEnv(v))
	}
}

// readSecret returns the literal value when set, otherwise the env
// var's value, otherwise "".
func readSecret(literal, envName string) string {
	if literal != "" {
		return literal
	}
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
}

// expandEnv expands `${VAR}` and `$VAR` references in s using
// os.Getenv. Used by the per-mirror Headers bag so the YAML can
// reference secrets by env-var name.
func expandEnv(s string) string {
	return os.Expand(s, os.Getenv)
}

// HostOf returns the host portion of a URL for log fields. Empty
// when the URL is malformed; callers fall back to the raw URL in
// that case.
func HostOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
		rest = rest[:slash]
	}
	return rest
}
