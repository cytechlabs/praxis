# Release notes template

The publish workflow creates the GitHub Release with a generated release index
as the body: source commit, image digests, SBOM files, agent artifact checksums,
and the security gates that ran. That part is machine-generated on purpose, so
it cannot describe artifacts that were not published.

This template is the human summary. After the release exists, edit it and put
this above the generated index, filling in the `<…>` placeholders. Keep it
public-facing: describe capabilities, not internal issue IDs or process details.

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

Stable releases also publish `:<X.Y>` and `:latest` tags. Those move; the
digests in the release index below do not. See
[docs/ghcr-release-operations.md](ghcr-release-operations.md).

### Fleet agent

Agent artifacts are published under the matching `agent-v<X.Y.Z>` tag:

- `praxis-agent-v<X.Y.Z>-linux-amd64.tar.gz`
- `praxis-agent-v<X.Y.Z>-linux-arm64.tar.gz`
- `praxis-agent-v<X.Y.Z>-linux-amd64-sbom.cdx.json`
- `praxis-agent-v<X.Y.Z>-linux-arm64-sbom.cdx.json`
- `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem`

The tarballs are built reproducibly with a pinned Go toolchain: rebuilding
the release tag produces artifacts with the same checksums.

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

- `release-index.json` is the machine-readable release record: source commit,
  image digests, SBOM files, agent artifact checksums, and the gates that ran.
- A CycloneDX 1.6 SBOM for each image is attached to this release
  (`sbom-backend-<X.Y.Z>.cdx.json`, `sbom-frontend-<X.Y.Z>.cdx.json`),
  generated from the published digests rather than from the tags. The agent's
  per-architecture SBOMs are CycloneDX 1.5.
- Build provenance and the SBOM are attested for each image with keyless GitHub
  OIDC. There is no public key to distribute:

  ```sh
  gh attestation verify oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
      --repo cytechlabs/praxis
  ```

- Trivy ran against both production images at release time; no unaccepted
  `CRITICAL` findings. SARIF reports for `HIGH` and below are in the
  `security-reports` build artifact on the corresponding CI run.

### Upgrade notes

`<Link to the version-specific upgrade notes, e.g. docs/upgrade-notes-1-0.md,
and call out any migration or configuration steps.>`

### Known limitations

- `<Carry forward from the changelog / upgrade notes.>`

### Verification checklist

Confirm before publishing (full runbook:
[docs/release-checklist.md](release-checklist.md)):

- [ ] Package versions aligned to `<X.Y.Z>` (root, frontend, backend).
- [ ] CI green on the tagged ref; publish `verify` and `build` gates passed.
- [ ] GHCR image tags and digests present and matching `release-index.json`.
- [ ] SBOM / Trivy / SARIF reviewed; image attestations verify.
- [ ] Agent tarball checksums and cosign signature verified.
- [ ] Post-publish smoke passed with `PRAXIS_VERSION=<X.Y.Z>`.
