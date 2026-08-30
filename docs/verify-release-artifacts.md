---
title: Verify release artifacts
description: Confirm the images and the agent tarball you are about to run were built by the Praxis release pipeline.
---

Do this before a deployment goes into service, and again after any upgrade.
Verification proves that what you are running came from the published source
through the published pipeline, rather than trusting a tag or a download page.

Everything here uses public artifacts. No account or credential is needed for a
public release.

## What a release publishes

A release publishes exactly two container images:

```text
ghcr.io/cytechlabs/praxis-backend
ghcr.io/cytechlabs/praxis-frontend
```

and, under the matching `agent-vX.Y.Z` tag, the fleet agent as signed tarballs.
The agent is never a container image.

Each release also attaches a CycloneDX SBOM per image, the agent checksums and
their signature, and `release-index.json`, which is the machine-readable record
of the release: source commit, every component, image digests, SBOM filenames,
and the agent artifact checksums.

## Tags move; digests do not

```text
ghcr.io/cytechlabs/praxis-backend:1.0.1                  a tag
ghcr.io/cytechlabs/praxis-backend@sha256:<64 hex chars>  a digest
```

`X.Y.Z` is not repointed once published. `X.Y` moves to the newest patch in that
line and `latest` moves to the newest stable release, so neither is a stable
description of what you are running.

**Deploy digests.** Verification anchors to a digest, and pinning one is what
makes a later verification meaningful.

## Verify an image

Resolve the digest without pulling the layers, then compare it against the
release index:

```sh
docker buildx imagetools inspect ghcr.io/cytechlabs/praxis-backend:1.0.1
```

Pull by digest and confirm the build provenance:

```sh
docker pull ghcr.io/cytechlabs/praxis-backend@sha256:<digest>

gh attestation verify \
    oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis
```

Praxis signs with keyless GitHub OIDC attestations, so there is no public key to
distribute and no signing key to protect. The identity being verified is the
publishing workflow itself, recorded in a public transparency log. Verification
fails, correctly, if someone republished the same tag from somewhere else.

`gh attestation verify` needs GitHub CLI 2.49 or newer.

To pin the signer identity explicitly rather than by repository:

```sh
cosign verify-attestation \
    --type slsaprovenance \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/publish.yml@refs/tags/v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    ghcr.io/cytechlabs/praxis-backend@sha256:<digest>
```

Repeat for `praxis-frontend`.

## Check the SBOM describes what you pulled

```sh
gh release download v1.0.1 --pattern 'sbom-*.cdx.json'

jq -r '.metadata.component.name' sbom-backend-1.0.1.cdx.json
```

The image named there must be the digest you pulled. An SBOM that names a
different image is from another build; do not ship it.

The SBOM is itself attested, so you can confirm it came from the release rather
than from the download page:

```sh
gh attestation verify oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis --predicate-type https://cyclonedx.org/bom
```

## Read the release index

```sh
gh release download v1.0.1 --pattern release-index.json

jq -r '.source.commit, (.components[] | "\(.name) \(.digest // "n/a")")' \
    release-index.json
```

Every component of a release is built from one source commit, including the
agent. The publishing pipeline resolves the agent tag to the commit it actually
names and refuses to publish if it is not the same commit the application was
verified at, so the index describes one whole product rather than parts from
two builds.

## Verify the agent tarball

The agent ships a `checksums.txt` covering the per-architecture tarballs and
their SBOMs, plus a keyless cosign signature over that file. Verify in two
steps, and **verify before extracting**.

```sh
cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/agent-release.yml@refs/tags/agent-v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    checksums.txt

sha256sum -c checksums.txt
```

The first step anchors trust to the workflow identity that built the release.
The second anchors the tarballs and SBOMs to that signed file. A tarball that
fails either check should be discarded, not installed.

Confirm what you installed afterwards:

```sh
praxis-agent version --json
```

The JSON form carries the full 40-character commit SHA, which is the identifier
to quote in a bug report. `stamped: false` means the binary is a local build
rather than a published release artifact. Agent release builds are reproducible,
so version, commit, and Go toolchain fully identify a binary; there is no build
timestamp to compare.

## When verification fails

| Symptom | Usual cause |
|---|---|
| `gh attestation verify` fails on an image you believe is good | Verifying a tag instead of a digest, or the wrong `--repo`. Use `oci://...@sha256:<digest>`. |
| `unauthorized: unauthenticated` on an anonymous pull | The package is not public yet. |
| SBOM names a different image | The SBOM is from another build. Do not deploy it. |
| `cosign verify-blob` fails on the agent | The signature does not match the identity for this repository, or the files are from different releases. Re-download all three together. |

A verification failure is a stop, not a warning. Do not deploy an artifact whose
provenance you could not confirm.
