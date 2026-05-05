# Corporate environments

Notes for running Astinus inside a firewalled corporate network:
internal Artifactory / Harbor / Nexus, mTLS-protected mirrors,
proxies, and air-gapped runners. If you only need basic auth via
`docker login`, you don't need this page.

There are two configs that look superficially similar but answer
different questions:

| Config | Question it answers |
|---|---|
| `--config astinus.yaml` (`registries:` section) | How do I pull the **container image**? |
| `--mirrors-config mirrors.yaml` (`mirrors:` section) | How do I fetch **package metadata** from npm / PyPI / Maven / Go? |

Both can coexist in the same run.

## Image registry: per-host auth and TLS

Most teams use `docker login` once on the runner; Astinus reads
`~/.docker/config.json` automatically. You only need this section
if you want explicit control — token rotation, custom CA, mTLS,
or a proxy on the registry path specifically.

```yaml
# astinus.yaml
registries:
  - host: artifactory.corp.example
    auth:
      provider: artifactory
      mode: token              # token | apikey | oidc
      token_env: ARTIFACTORY_TOKEN
    tls:
      ca_cert: /etc/ssl/corp-ca.pem
      client_cert: /etc/ssl/client.pem
      client_key:  /etc/ssl/client.key
    proxy: http://proxy.corp.example:3128

  - host: harbor.corp.example
    auth:
      provider: docker-config  # let docker handle it
```

```bash
astinus enrich --config astinus.yaml ...
```

The Artifactory provider is the only "native" one — it understands
Token / API Key / OIDC modes against the JFrog REST API. For ECR /
GCR / ACR, Astinus relies on the cloud CLI having already populated
`~/.docker/config.json` (`aws ecr get-login-password | docker
login`, `gcloud auth configure-docker`, `az acr login`).

### Per-host env-var credentials

For one-off runs you can skip the YAML and pass credentials via
env:

```bash
ASTINUS_REGISTRY_ARTIFACTORY_CORP_EXAMPLE_TOKEN="$TOKEN" \
  astinus enrich --image artifactory.corp.example/team/img:tag ...
```

The host name gets uppercased with `.` and `-` replaced by `_`.
Three vars are read per host: `_USERNAME` + `_PASSWORD`, or
`_TOKEN`. CA bundle / mTLS / proxy still need either
`--ca-cert` / `--config astinus.yaml` or the standard
`HTTPS_PROXY` env var — they're not per-host env-driven.

Generic `REGISTRY_USERNAME` / `REGISTRY_PASSWORD` /
`REGISTRY_TOKEN` are also honoured (apply to every host); the
per-host variant wins when both apply.

## Package mirrors: replace vs fallback

Astinus's registry enricher fetches license / homepage /
repository / hashes from the public package registries. In a
corporate env, point it at your internal mirror:

```yaml
# mirrors.yaml
version: 1
mirrors:
  - ecosystem: npm
    url: https://artifactory.corp.example/api/npm/npm-virtual
    mode: replace
    auth:
      type: bearer
      token_env: ARTIFACTORY_TOKEN
```

```bash
astinus enrich --mirrors-config mirrors.yaml ...
```

Pick `mode` deliberately:

- **`replace`** — strict. Only your mirror is queried, even on a
  404. The right default for air-gapped / regulated environments
  where outbound calls to npmjs.com / pypi.org are forbidden.
- **`fallback`** — pragmatic. Your mirror first, then upstream
  on 404 or transient failure. Use when caching matters but
  occasional gaps in the mirror's index are acceptable.

You can chain entries — multiple mirrors of the same ecosystem
are tried in declaration order, with all `replace` entries before
any `fallback` entries.

## mTLS to a corporate mirror

If the mirror requires a client certificate:

```yaml
mirrors:
  - ecosystem: npm
    url: https://npm.corp.example
    mode: replace
    tls:
      ca_cert:     /etc/ssl/corp-ca.pem
      client_cert: /etc/ssl/client.pem
      client_key:  /etc/ssl/client.key
    auth:
      type: bearer
      token_env: NPM_BEARER
```

PEM-encoded files. The CA bundle is added to (not replaces) the
system root pool, so you can keep mixing public + corporate
endpoints.

If the same CA is needed for the image-pull path, point
`--ca-cert` at it too — that flag also reaches cosign via
`SSL_CERT_FILE`, so signing through a corporate Sigstore
deployment uses the same trust material.

## HTTP proxies

Astinus uses the standard `http.ProxyFromEnvironment` —
`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` work as you'd expect.
Embed credentials in the URL if your proxy needs them:

```bash
export HTTPS_PROXY="http://ci-bot:hunter2@proxy.corp.example:3128"
export NO_PROXY="artifactory.corp.example,.corp.example"
astinus enrich ...
```

The image pull, package-mirror fetch, and cosign call all honour
these.

## Auth shapes for `mirrors.yaml`

```yaml
# Bearer token
auth:
  type: bearer
  token_env: ARTIFACTORY_TOKEN

# Basic auth
auth:
  type: basic
  username: ci-bot
  password_env: ARTIFACTORY_PASSWORD

# Custom header — JFrog API key, GHCR token, etc.
auth:
  type: header
  header_name: X-JFrog-Art-Api
  header_value_env: ARTIFACTORY_API_KEY
```

For all three, the literal `token` / `password` / `header_value`
fields exist but are discouraged — use the `*_env` variants and
inject from your CI's secret store.

## Caching for fast CI

```bash
astinus enrich \
  --registry-cache-dir /var/cache/astinus \
  --registry-cache-ttl 168h \
  ...
```

The cache key includes the package coordinates + the mirror URL,
so switching between dev and prod mirror configs doesn't return
stale entries. Default TTL is 7 days — published package metadata
rarely changes.

## What's safe to leak in CI logs

`--log-level debug` will surface URLs, status codes, and timing
for every outbound call. Authorization headers are NOT logged at
any verbosity. Cosign's argv is printed at info level with
`--key`, `--cert`, `--token`, `--certificate` values redacted to
`<redacted>` — you can tell from the log whether the right flag
was passed without exposing the file path.

If you're shipping logs off-site, structured JSON
(`--log-format json`) makes redaction-at-the-pipeline easier than
pattern-matching on text.

## Common failures

**`registry: pull "...": 401 Unauthorized`** — `docker login`
hasn't run, or the token in `--config` is wrong / expired.

**`tls: failed to verify certificate`** — the registry's CA isn't
in the system pool. Add it via `--ca-cert /path/to/corp-ca.pem`
or the per-host `tls.ca_cert` in `astinus.yaml`.

**`tls: handshake failure: certificate required`** — the mirror
is in mTLS mode but `tls.client_cert` / `client_key` weren't
configured.

**`registry-mirror: ... 404 Not Found` (and the run still
succeeds)** — `replace` mode and the mirror doesn't have the
package. The component just doesn't get the metadata; it's not
fatal. Switch to `fallback` if you want public-upstream
backstop, or accept the gap.

**`--no-network: image "..." requires a registry pull`** — you
asked for air-gapped mode but pointed `--image` at a registry
ref. Use `archive://` or `oci://` instead, or load the image into
a local daemon and use `docker-daemon://name:tag`.

## Limitations to know about

`http.ProxyFromEnvironment` (Go's standard library) hard-codes a
loopback bypass — requests to 127.0.0.1 / ::1 / localhost skip
the proxy. This isn't an Astinus quirk; it's true of every Go
binary. If you're testing the proxy path locally, use a
non-loopback address (or a real corporate proxy with a
non-loopback target).
