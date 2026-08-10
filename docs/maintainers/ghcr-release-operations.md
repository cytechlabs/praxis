# GHCR release operations

This is the operator guide to the GitHub Container Registry side of a Praxis
release: what the registry is, what has to be configured once by hand, how to
publish, and how to verify or roll back what was published.

It is written for someone who knows Harbor or Docker Hub. GHCR is close enough
to both to be misleading, so the differences are called out where they matter
rather than left to be discovered during a release.

The full release runbook, including the application gates and the agent, is
[docs/maintainers/release-checklist.md](release-checklist.md).

---

## 1. What GHCR is, in Harbor and Docker Hub terms

`ghcr.io` is GitHub's container registry. One instance serves all of GitHub;
there is no Praxis registry to deploy, patch, or back up.

| Concept | Harbor | Docker Hub | GHCR |
|---|---|---|---|
| Namespace | project | user or organization | GitHub user or organization |
| Unit of access control | project, with per-project members and robots | repository | **package**, owned by the org, linked to a source repository |
| Machine credential | robot account | access token | the workflow's `GITHUB_TOKEN`, or a PAT outside Actions |
| Anonymous read | per-project "public" flag | public repository | per-package visibility flag |
| Retention/GC policy | project policy engine | limited | none built in; versions persist until deleted |

The important structural difference: **Harbor's project is not GHCR's
namespace.** In Harbor you set policy once on a project and every repository
inside inherits it. In GHCR, `cytechlabs` is only a name prefix. Visibility,
access, and retention are set on **each package individually**. Two packages in
the same organization can have different visibility, and making one public does
nothing to the other.

There are no robot accounts, no per-project quotas, and no retention or garbage
collection policies. Untagged versions accumulate until someone deletes them.

## 2. The two Praxis packages

A Praxis release publishes exactly two container packages:

```text
ghcr.io/cytechlabs/praxis-backend
ghcr.io/cytechlabs/praxis-frontend
```

These names are a public contract. Deployments pin them through
`PRAXIS_VERSION` in the production compose files, so renaming a package breaks
every existing install. Treat a rename as a breaking change with a migration
plan, not as a cleanup.

The fleet agent is **not** a container. It ships as signed tarballs on a GitHub
Release under the `agent-vX.Y.Z` tag and never appears in GHCR. See
[docs/maintainers/agent-release.md](agent-release.md).

### Where the packages appear in GitHub

- Organization view: `https://github.com/orgs/cytechlabs/packages`
- Package view: `https://github.com/orgs/cytechlabs/packages/container/package/praxis-backend`
- Every pushed version, its tags, and its digest are listed on the package page.
- Package settings (visibility, repository link, admins, delete) are behind
  **Package settings** on that page, not in the source repository's settings.

This split trips people up: the repository's Settings page has no package
controls, and the package's settings are not versioned in git. Everything in
section 4 is manual, one time, and invisible to code review.

## 3. Authentication

### Inside GitHub Actions (the normal case)

The publish workflow authenticates with the automatically provisioned
`GITHUB_TOKEN`:

```yaml
- uses: docker/login-action@... # v4
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}
```

No PAT, no stored registry credential, and nothing to rotate. The token is
scoped to the run and expires with it. It can push only because the publish job
declares `packages: write`.

### Outside Actions

You need a personal access token (classic) when you are:

- pulling a **private** package from a workstation or a server;
- pushing or deleting a package version by hand; or
- pulling from a CI system that is not GitHub Actions.

Required scopes: `read:packages` to pull, `write:packages` to push,
`delete:packages` to remove a version.

```sh
echo "$GHCR_PAT" | docker login ghcr.io -u <github-username> --password-stdin
```

Fine-grained PATs do not currently cover the container registry; use a classic
token. This is the closest GHCR gets to a Harbor robot account, and it is worse:
the token belongs to a person, not to a project.

### Anonymous pulls

Once a package's visibility is **Public**, anyone can pull it with no login and
no GitHub account:

```sh
docker logout ghcr.io
docker pull ghcr.io/cytechlabs/praxis-backend:1.0.0
```

That is the end state Praxis wants: operators install without credentials. It
requires the one-time setting in the next section.

## 4. Visibility: the settings that are not in git

**Repository visibility and package visibility are separate.** A public source
repository does not make its packages public. The first push creates each
package as **private**, inheriting from the repository at creation time only,
and it stays that way until someone changes it in the GitHub UI.

Do this **once per package, after the first publish**, before telling anyone to
pull:

1. Open `https://github.com/orgs/cytechlabs/packages`.
2. Select `praxis-backend`, then **Package settings**.
3. Confirm **Manage Actions access** lists the `praxis` repository with at least
   **Write**. Without this the publish workflow cannot push to an existing
   package.
4. Under **Danger Zone**, choose **Change visibility** and set **Public**.
5. Repeat for `praxis-frontend`.

Then verify from a logged-out client:

```sh
docker logout ghcr.io
docker pull ghcr.io/cytechlabs/praxis-backend:<X.Y.Z>
```

> Not verifiable before a real release. The package does not exist until the
> first successful publish, so steps 2 to 5 and the anonymous pull can only be
> confirmed after a tag has been pushed. Everything in section 5 downwards
> assumes a published release exists.

Going public is effectively one way in practice. Anyone may have pulled and
pinned a digest; flipping back to private breaks them silently.

## 5. Tags versus digests

A tag is a mutable label. A digest is the immutable content address of the
image.

```text
ghcr.io/cytechlabs/praxis-backend:1.0.0                  <- tag, can be repointed
ghcr.io/cytechlabs/praxis-backend@sha256:<64 hex chars>  <- digest, cannot
```

Praxis publishes, per stable release:

| Tag | Moves? | Use |
|---|---|---|
| `X.Y.Z` | No, by policy | the release itself |
| `X.Y` | Yes, to the newest patch in that line | tracking patches |
| `latest` | Yes, to the newest stable release | demos and evaluation only |

Prerelease tags such as `v1.0.0-rc.1` publish **only** the exact version tag.
They never take `latest` or `X.Y`, so an rc cannot become what a new user pulls
by default.

The release workflow refuses to publish a version tag that already exists in
GHCR, so `X.Y.Z` is immutable in practice as well as by policy. Only `X.Y` and
`latest` are ever repointed, and only for a stable release.

Deploy digests, not tags. The release index attached to every GitHub Release
records the digest of each image for exactly this reason.

## 6. Publishing

### Dry run first

The publish workflow has a non-publishing path. Run it from the Actions tab:

- Workflow: **Publish**
- Run workflow, leave **dry_run** checked.

It runs the full gate (backend migrations and tests, frontend lint and type
check, release readiness), builds both production images, archives them, runs
the Trivy CRITICAL gate against those archives, generates both SBOMs, and
assembles a validation release index. Nothing is pushed, no release is created,
and no attestation is minted. The results are attached to the run as the
`release-validation-<version>` artifact.

A dry run from a branch describes the version in `package.json`. A dry run from
a tag describes that tag. A dry run may describe an agent release that has not
been cut yet; a real publish may not.

### Build once, promote what was gated

The images that reach GHCR are the images that passed the vulnerability gate.
The read-only `build` job is the only job that runs a Dockerfile: it builds each
image once, saves it to an archive, gates that archive, and uploads it. The
`publish` job loads those archives and pushes them unchanged.

This matters because two builds of one commit are not guaranteed to be the same
image. Base images and package repositories move, so a rebuild inside the
publish job could ship bytes no scanner ever saw, while the release record
claimed a passing gate. It also means the backend variant is decided once: if
you asked for a paid-capable build, the paid image is the one that is scanned
and the one that is promoted.

### Release the agent first

The release index is the whole-product record, so the application release
requires the matching agent release to exist already:

1. Cut and verify `agent-v<X.Y.Z>` (see [docs/maintainers/agent-release.md](agent-release.md)).
2. Then cut `v<X.Y.Z>` from the same commit.

Publishing the application first fails deliberately, with a message telling you
to publish the agent release. It does not fall back to recording the agent as
outstanding.

"From the same commit" is enforced, not just documented. Before it downloads the
agent manifest or promotes anything, the workflow resolves `agent-v<X.Y.Z>` to
the commit it actually names, peeling the tag object if it is annotated, and
refuses to continue unless that commit is the one the application release was
verified at. A matching version number is not evidence of a shared source: an
agent tag can be older than the application tag, or have been moved after the
fact, and the release index would then claim one whole-product commit for
artifacts built from two. A missing tag, an unresolvable one, or a mismatch all
stop the release.

If this check fails, do not move the agent tag to make it pass. Re-cut the
release from the intended commit.

### Publishing for real

Publishing happens on a tag push and nowhere else:

```sh
git tag v<X.Y.Z> <commit>
git push origin v<X.Y.Z>
```

The workflow then:

1. re-runs the verification gate against the tagged commit;
2. builds, archives, and gates both images once, under a read-only token;
3. refuses to continue unless the repository is `cytechlabs/praxis`, the ref is
   a `vX.Y.Z` tag, no GitHub Release exists for it, and neither image version is
   already published;
4. requires the matching `agent-v<X.Y.Z>` release, confirms that tag resolves to
   the same source commit, and downloads its checksum manifest;
5. loads the gated archives and pushes them to GHCR without rebuilding;
6. generates a CycloneDX SBOM from each **published digest**;
7. attests build provenance and the SBOM for each image through GitHub OIDC; and
8. creates the GitHub Release with both SBOMs, `release-index.json`, and the
   generated index as the release body.

Every existence check in step 3 fails closed. Only an authoritative not-found
answer lets publication continue: an expired token, a rate limit, a network
fault, or a registry outage aborts the release rather than being read as
"nothing is there". The one exception that is still safe is a package that has
never been published, which the registry refuses to describe at all; GitHub is
asked directly whether that package exists before the run proceeds.

Manual publishing from the Actions tab is possible (select a `vX.Y.Z` tag as the
ref and clear **dry_run**), but the tag must already exist. The workflow never
creates tags.

Re-running against an already published tag fails on purpose. Republishing means
deleting the release and the image versions deliberately first, which breaks
anyone who already verified them.

## 7. Verifying a published release

All commands below are the ones an end user runs. Run them yourself before
announcing a release.

The `gh attestation` subcommand needs a reasonably current GitHub CLI (2.49 or
newer) and a published image to verify against, so those commands cannot be
rehearsed before the first release. The `docker` and `jq` commands work against
any build, including a dry run's artifacts.

### Pull and record the digest

```sh
docker pull ghcr.io/cytechlabs/praxis-backend:<X.Y.Z>
docker buildx imagetools inspect ghcr.io/cytechlabs/praxis-backend:<X.Y.Z>
```

`imagetools inspect` prints the manifest digest without pulling the layers,
which is the fastest way to answer "what is `latest` pointing at right now".
Compare it against the digest in the release index.

### Pull by digest

```sh
docker pull ghcr.io/cytechlabs/praxis-backend@sha256:<digest>
docker buildx imagetools inspect ghcr.io/cytechlabs/praxis-backend@sha256:<digest> --raw
```

### Verify provenance and the SBOM attestation

Praxis signs with keyless GitHub OIDC attestations. There is no public key to
distribute and no signing key to protect: the identity is the workflow itself,
recorded in a public transparency log.

```sh
gh attestation verify \
    oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis
```

This confirms the image was built by this repository's publish workflow from the
commit it claims. Verification fails, correctly, if someone republishes the same
tag from elsewhere.

To inspect rather than just verify, or to check the signer identity explicitly:

```sh
gh attestation verify \
    oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis --format json

cosign verify-attestation \
    --type slsaprovenance \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/publish.yml@refs/tags/v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    ghcr.io/cytechlabs/praxis-backend@sha256:<digest>
```

`gh attestation verify` needs `gh auth login` for private packages; a public
package needs no credentials.

### Inspect the SBOM

Each release attaches `sbom-backend-<X.Y.Z>.cdx.json` and
`sbom-frontend-<X.Y.Z>.cdx.json`. They are CycloneDX 1.6 JSON generated from the
published digests, not from the tags. The agent's own SBOMs are CycloneDX 1.5,
because a different generator produces them; both are valid CycloneDX and the
release index records each component's spec version.

```sh
gh release download v<X.Y.Z> --pattern 'sbom-*.cdx.json'

# What it is, and which image it describes.
jq '{format: .bomFormat, spec: .specVersion, image: .metadata.component.name}' \
    sbom-backend-<X.Y.Z>.cdx.json

# The image named above must be the digest you pulled.
jq -r '.metadata.component.name' sbom-backend-<X.Y.Z>.cdx.json

# Component count and a specific dependency.
jq '.components | length' sbom-backend-<X.Y.Z>.cdx.json
jq -r '.components[] | select(.name == "cryptography") | "\(.name) \(.version)"' \
    sbom-backend-<X.Y.Z>.cdx.json
```

The SBOM attestation lets you check that the file came from the release rather
than from the download page:

```sh
gh attestation verify oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis --predicate-type https://cyclonedx.org/bom
```

### Read the release index

`release-index.json` is the machine-readable release record: source commit,
version, every component, image digests, SBOM file names, the agent artifact
checksums, and the security gates that ran.

```sh
gh release download v<X.Y.Z> --pattern release-index.json
jq -r '.source.commit, (.components[] | "\(.name) \(.digest // "n/a")")' release-index.json
```

## 8. Moving tags and rolling back

### Moving `latest` and `X.Y`

These move only as part of publishing a stable release, and only by the publish
workflow. Do not repoint them by hand: a hand-pushed tag has no provenance
attestation tying it to a build, so `gh attestation verify` on whatever `latest`
resolves to would no longer prove anything useful.

If `latest` must be corrected, publish a new patch release. That is slower and
correct, rather than fast and unverifiable.

### Rolling back a deployment

Rollback does not touch the registry. Pick the previous release's digest and
redeploy it:

```sh
# 1. Find the digest of the release you want, from its release index.
gh release download v<previous> --pattern release-index.json
jq -r '.components[] | select(.kind == "container-image") | "\(.name) \(.digest)"' \
    release-index.json

# 2. Confirm it is still pullable and is what it claims to be.
docker pull ghcr.io/cytechlabs/praxis-backend@sha256:<previous-digest>
gh attestation verify oci://ghcr.io/cytechlabs/praxis-backend@sha256:<previous-digest> \
    --repo cytechlabs/praxis

# 3. Redeploy pinned to the previous version.
export PRAXIS_VERSION=<previous>
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

Never roll back by deleting the bad version from GHCR. Deletion breaks anyone
who pinned that digest and destroys the evidence of what shipped. Publish a
fixed version forward instead.

Deleting a package version is possible from the package page's **Danger Zone**
and is irreversible. Reserve it for a version that leaked a secret, and treat it
as an incident rather than a cleanup.

## 9. Failure modes

| Symptom | Cause | Where to look |
|---|---|---|
| `denied: permission_denied: write_package` | The publish job lacks `packages: write`, or the package's Actions access does not include this repository | Job `permissions:` in `.github/workflows/publish.yml`; package settings, **Manage Actions access** |
| `denied: denied` on pull from a workstation | Package is private and you are not logged in, or your PAT lacks `read:packages` | Package settings, **visibility**; PAT scopes |
| `unauthorized: unauthenticated` for anonymous users | Package visibility is still Private | Section 4 |
| Publish job skipped entirely | Ref is not a `vX.Y.Z` tag, `dry_run` was left checked, or the repository is a fork | The job's `if:` condition and the run's trigger |
| `release <tag> already exists; refusing to overwrite` | The tag was published before | Intentional. Delete deliberately or publish a new version |
| `<image> already exists; refusing to overwrite it` | That image version is already in GHCR | Intentional, as above |
| Attestation step fails with an OIDC error | The job is missing `id-token: write` or `attestations: write` | Job `permissions:` |
| `gh attestation verify` fails on a good image | Verifying a tag rather than a digest, or the wrong `--repo` | Use `oci://...@sha256:<digest>` |
| SBOM names a different image than you pulled | The SBOM is from another build | Do not ship it. The release workflow already fails on this |
| Release readiness fails on version alignment | Package metadata does not match the tag | `scripts/check-release-readiness.sh <X.Y.Z>` |

Two GitHub settings, both outside version control, are worth confirming when a
publish fails in a way the table does not explain:

- **Package settings > Manage Actions access.** The most common cause. A
  package that does not grant this repository write access cannot be pushed to,
  whatever the workflow asks for.
- **Organization or enterprise Actions policy.** Policy above the repository can
  restrict which actions may run, which blocks SHA-pinned third-party actions
  unless they are allowed, and can cap what `GITHUB_TOKEN` may be granted.

Note what is *not* the cause: the repository's **Settings > Actions > General >
Workflow permissions** default. That setting decides the token scopes for
workflows that declare no `permissions:` key. This workflow declares its
permissions explicitly on every job, so the publish job's `packages: write`
applies regardless of whether the repository default is read-only. Do not
loosen the repository-wide default to fix a publish failure; it grants every
other workflow more than it needs and will not fix this one.

## 10. What cannot be checked before the first release

These are real gaps, not oversights. Confirm each one during the first publish
and record the result in the release checklist:

- the packages exist under the expected names;
- package visibility is Public and an anonymous `docker pull` succeeds;
- the package's Actions access lists the `praxis` repository;
- `gh attestation verify` succeeds against a published digest;
- the SBOM attestation predicate is retrievable from the registry; and
- `latest` and `X.Y` resolve to the digests recorded in the release index.
