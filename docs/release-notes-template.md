# Release notes template

Copy this into the GitHub Release body when cutting a release, and fill in the
`<…>` placeholders. Keep it public-facing: describe capabilities, not internal
issue IDs or process details. The publish workflow appends auto-generated notes
and the container-pull snippet below the body you provide, so this template
focuses on the human summary and the verification checklist.

---

## Praxis `<vX.Y.Z>`

`<One or two sentences: what this release is and who should upgrade.>`

### Highlights

- `<Capability-area change, in product terms.>`
- `<…>`

### Container images

```sh
docker pull ghcr.io/cytechlabs/praxis-backend:<X.Y.Z>
docker pull ghcr.io/cytechlabs/praxis-frontend:<X.Y.Z>
```

Pin the release in `.env`:

```sh
PRAXIS_VERSION=<X.Y.Z>
```

Stable releases also publish `:<X.Y>` and `:latest` tags.

### Fleet agent

Agent artifacts are published under the matching `agent-v<X.Y.Z>` tag:

- `praxis-agent-v<X.Y.Z>-linux-amd64.tar.gz`
- `praxis-agent-v<X.Y.Z>-linux-arm64.tar.gz`
- `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem`

Verify before installing (see
[agent/packaging/README.md](../agent/packaging/README.md)):

```sh
cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/agent-release.yml@refs/tags/agent-v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    checksums.txt
sha256sum -c checksums.txt
```

### Supply chain

- CycloneDX 1.5 SBOMs for each image are attached to this release
  (`sbom-backend-<X.Y.Z>.cdx.json`, `sbom-frontend-<X.Y.Z>.cdx.json`).
- CI ran Trivy against both production images; no unaccepted `CRITICAL`
  findings. SARIF reports for `HIGH` and below are in the `security-reports`
  build artifact on the corresponding CI run.

### Upgrade notes

`<Link to the version-specific upgrade notes, e.g. docs/upgrade-notes-1.0.md,
and call out any migration or configuration steps.>`

### Known limitations

- `<Carry forward from the changelog / upgrade notes.>`

### Verification checklist

Confirm before publishing (full runbook:
[docs/release-checklist.md](release-checklist.md)):

- [ ] Package versions aligned to `<X.Y.Z>` (root, frontend, backend).
- [ ] CI green on the tagged ref; publish `verify` gate passed.
- [ ] GHCR image tags and digests present and correct.
- [ ] SBOM / Trivy / SARIF reviewed.
- [ ] Agent tarball checksums and cosign signature verified.
- [ ] Post-publish smoke passed with `PRAXIS_VERSION=<X.Y.Z>`.
