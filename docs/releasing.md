# Releasing Astinus

The release pipeline is fully automated by
`.github/workflows/release.yml`, triggered by pushing a `v*` tag.
Operators only need to:

## 1. Prepare CHANGELOG

- Move "Unreleased" entries under a new `## vX.Y.Z — YYYY-MM-DD`
  heading
- Verify the date and version match the tag you'll push
- Commit the CHANGELOG bump on `dev`, merge to `main` via PR

## 2. Tag

```bash
git checkout main
git pull
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

`release.yml` triggers on the tag push.

## 3. Verify the draft release

The workflow creates a **draft** release on GitHub. Check:

- 5 archives — `linux_x86_64.tar.gz`, `linux_arm64.tar.gz`,
  `darwin_x86_64.tar.gz`, `darwin_arm64.tar.gz`,
  `windows_x86_64.zip`
- `astinus_vX.Y.Z_SHA256SUMS` + `.sig` + `.pem`
  (cosign keyless)
- Container image pushed to `ghcr.io/psyf8t/astinus:vX.Y.Z` and
  `:latest` (multi-arch manifest)
- Release notes match the CHANGELOG section

## 4. Smoke-test before publishing

```bash
# Pick the platform you can run
curl -L -o /tmp/astinus.tar.gz \
  https://github.com/psyf8t/astinus/releases/download/vX.Y.Z/astinus_vX.Y.Z_linux_x86_64.tar.gz
tar -xzf /tmp/astinus.tar.gz -C /tmp
/tmp/astinus version
# Expect: astinus vX.Y.Z (commit ..., built ...)

# Verify SHA256
curl -L -o /tmp/SHA256SUMS \
  https://github.com/psyf8t/astinus/releases/download/vX.Y.Z/astinus_vX.Y.Z_SHA256SUMS
(cd /tmp && sha256sum -c SHA256SUMS --ignore-missing)

# Verify cosign signature
curl -L -O \
  https://github.com/psyf8t/astinus/releases/download/vX.Y.Z/astinus_vX.Y.Z_SHA256SUMS.sig
curl -L -O \
  https://github.com/psyf8t/astinus/releases/download/vX.Y.Z/astinus_vX.Y.Z_SHA256SUMS.pem
cosign verify-blob \
  --certificate astinus_vX.Y.Z_SHA256SUMS.pem \
  --signature astinus_vX.Y.Z_SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/psyf8t/astinus/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  astinus_vX.Y.Z_SHA256SUMS
# Expect: Verified OK
```

## 5. Promote to "released"

Edit the draft release and click **Publish release**.

## 6. Post-release

- Open `dev` and start a new "Unreleased" CHANGELOG section
- Pull `main` into `dev` so future commits build on top of the
  release commit:

  ```bash
  git checkout dev
  git pull origin main
  git push origin dev
  ```

## If something goes wrong

The workflow creates the release as **draft** specifically so you
can throw it away without consequences. If the snapshot looks
wrong, the binaries don't run, or the cosign verification fails:

```bash
gh release delete vX.Y.Z --yes
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
```

Fix the underlying issue, force-push the bumped tag, and the
workflow re-runs.

## Local validation before pushing a tag

`goreleaser release --snapshot --clean` runs the full pipeline
locally. Use it before pushing a tag to catch config errors:

```bash
# Skip docker (needs buildx + ghcr login) and sign (needs OIDC)
# locally — both run on CI runners.
goreleaser release --snapshot --clean --skip=docker,sign
ls dist/
```

You should see the same 5 archives + `SHA256SUMS` + per-platform
binaries the CI workflow will produce.
