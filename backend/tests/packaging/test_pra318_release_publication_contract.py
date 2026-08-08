"""PRA-318: the whole-product publication contract.

The application ships as two GHCR container images plus a release record that
tells a consumer what was published and how to verify it. Almost none of that
is exercised until a tag is pushed, and by then a mistake is public. These
tests are the earlier check.

They cover three things:

- **A publish path that cannot fire by accident.** The workflow must keep its
  validation jobs read-only, refuse to publish from a fork or a non-tag ref,
  pin every action by commit, and never overwrite a published version.
- **The public package contract.** Deployments pin ``praxis-backend`` and
  ``praxis-frontend`` by name and the release record identifies them by
  digest, so both survive here as assertions rather than conventions.
- **A release index that cannot describe artifacts that were not built.**
  ``build_release_index.py`` is driven with mismatched, stale, and incomplete
  inputs to confirm it fails instead of publishing a plausible-looking record.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
BUILD_INDEX = REPO_ROOT / "scripts" / "build_release_index.py"
ABSENCE = REPO_ROOT / "scripts" / "check-release-absence.sh"
TAG_COMMIT = REPO_ROOT / "scripts" / "check-tag-commit.sh"
PROMOTE = REPO_ROOT / "scripts" / "promote-release-images.sh"
READINESS = REPO_ROOT / "scripts" / "check-release-readiness.sh"
GHCR_RUNBOOK = REPO_ROOT / "docs" / "ghcr-release-operations.md"

REGISTRY = "ghcr.io"
OWNER = "cytechlabs"
BACKEND_PACKAGE = "praxis-backend"
FRONTEND_PACKAGE = "praxis-frontend"

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
COMMIT = "45eff6954a3e471f241c1af51d901280fec29c86"
SPEC_VERSION = "1.6"


def _workflow_text() -> str:
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def _job_block(name: str) -> str:
    """Return the body of one job from the publish workflow.

    The backend image carries no YAML parser, so the workflow is read as text
    and sliced on indentation: a job body is every line indented deeper than
    the ``  <name>:`` header that opens it."""
    lines = _workflow_text().splitlines()
    header = f"  {name}:"
    try:
        start = lines.index(header)
    except ValueError:  # pragma: no cover - guarded by the assertion below
        raise AssertionError(f"job {name!r} not found in {PUBLISH_WORKFLOW}") from None
    body = []
    for line in lines[start + 1 :]:
        if line.strip() and not line.startswith("    "):
            break
        body.append(line)
    return "\n".join(body)


def _permissions(job: str) -> list:
    """Return the entries of a job's ``permissions:`` mapping."""
    lines = job.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == "permissions:"), None
    )
    assert start is not None, "job declares no permissions block"
    entries = []
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= 4:
            break
        entries.append(line.split("#", 1)[0].strip())
    return entries


# --------------------------------------------------------------- publish path


def test_publish_workflow_defaults_to_no_permissions():
    assert re.search(r"^permissions: \{\}$", _workflow_text(), re.MULTILINE)


def test_publish_workflow_triggers_only_on_application_tags():
    """Agent releases are tagged ``agent-vX.Y.Z``. This workflow must not fire
    on those, or an agent release would republish the application images."""
    text = _workflow_text()
    tag_patterns = re.findall(r"^\s+- '(v?[^']*\*[^']*)'", text, re.MULTILINE)
    assert tag_patterns == ["v*.*.*", "v*.*.*-*"]


def test_publish_workflow_exposes_a_dry_run_that_defaults_to_true():
    """A manual run must not publish unless the operator asks for it."""
    text = _workflow_text()
    dispatch = text.split("workflow_dispatch:", 1)[1].split("\npermissions:", 1)[0]
    assert "dry_run:" in dispatch
    assert "type: boolean" in dispatch
    assert "default: true" in dispatch


def test_validation_jobs_hold_read_only_tokens():
    """Everything up to the publish decision runs without write access, so a
    fault in the build or scan path cannot reach the registry."""
    for job in ("verify", "build"):
        assert _permissions(_job_block(job)) == ["contents: read"], job


def test_build_job_never_pushes():
    """The build job produces the images the publish job promotes. If it could
    push, the read-only boundary above would be decorative."""
    build = _job_block("build")
    assert "push: false" in build
    assert "push: true" not in build


def test_publish_job_runs_no_dockerfile_build():
    """The bytes that reach the registry must be the bytes that passed the
    vulnerability gate. A second build of the same commit can differ, because
    base images and package repositories move, and the release index would then
    claim a gate result that the published images never earned."""
    publish = _job_block("publish")
    assert "docker/build-push-action" not in publish
    assert "docker build" not in publish
    assert "Dockerfile" not in publish
    # It promotes what the gate accepted instead.
    assert "docker load --input" in publish
    assert "scripts/promote-release-images.sh" in publish


def test_only_the_build_job_builds_images():
    """One build per release. Anything else reintroduces the drift above."""
    text = _workflow_text()
    assert text.count("docker/build-push-action@") == 2
    assert _job_block("build").count("docker/build-push-action@") == 2


def test_gate_scans_the_archive_that_is_promoted():
    """Scanning the archive, rather than a daemon image that merely shares a
    tag with it, is what makes the gate a statement about the promoted bytes."""
    build = _job_block("build")
    assert "docker save --output images/backend.tar" in build
    assert "docker save --output images/frontend.tar" in build
    for archive in ("images/backend.tar", "images/frontend.tar"):
        assert f"input: {archive}" in build, archive
    # The archives are saved before the gate runs against them.
    assert build.index("docker save --output") < build.index(
        "input: images/backend.tar"
    )
    # And they are the artifact the publish job consumes.
    assert "release-images-${{ needs.verify.outputs.version }}" in build
    assert "release-images-${{ needs.verify.outputs.version }}" in _job_block("publish")


def test_promoted_images_are_the_gated_references():
    """The archive has to carry the exact references the gate accepted, and the
    publish job refuses to continue if it does not."""
    publish = _job_block("publish")
    assert "docker image inspect" in publish
    for package in ("BACKEND_PACKAGE", "FRONTEND_PACKAGE"):
        assert (
            '${REGISTRY}/${OWNER}/${%s}:${VERSION}" >/dev/null' % package in publish
        ), package


def test_digests_sbom_and_attestations_derive_from_the_promotion():
    """Everything recorded about a published image traces back to the digest
    the promotion produced, not to a tag that could be repointed."""
    publish = _job_block("publish")
    for step in ("backend", "frontend"):
        digest = "steps.promote.outputs.%s_digest" % step
        # SBOM scanned by digest.
        assert (
            "image-ref: ${{ env.REGISTRY }}/${{ env.OWNER }}/${{ env.%s_PACKAGE }}@${{ %s }}"
            % (step.upper(), digest)
            in publish
        ), step
        # Attested by digest.
        assert "subject-digest: ${{ %s }}" % digest in publish, step
        # Recorded in the index by digest.
        assert "_DIGEST}" in publish


def test_backend_variant_is_decided_once_and_gated():
    """The read-only job used to build a free backend while publish built a
    paid one, so the published paid image was never scanned. The variant is now
    resolved in the gate job and consumed by the single build."""
    verify = _job_block("verify")
    assert "praxis_ee=1" in verify
    assert "praxis_ee=0" in verify

    build = _job_block("build")
    assert "PRAXIS_EE=${{ needs.verify.outputs.praxis_ee }}" in build
    assert "if: ${{ needs.verify.outputs.praxis_ee == '1' }}" in build
    # No variant decision survives in the publish job.
    assert "PRAXIS_EE" not in _job_block("publish")


def test_publish_job_holds_only_release_registry_and_attestation_permissions():
    assert sorted(_permissions(_job_block("publish"))) == [
        "attestations: write",
        "contents: write",
        "id-token: write",
        "packages: write",
    ]


def test_publish_job_is_gated_on_the_upstream_repository_and_publish_mode():
    """Prevents a fork, or a validation run, from reaching the registry."""
    publish = _job_block("publish")
    condition = publish.split("if:", 1)[1].split("runs-on:", 1)[0]
    assert "github.repository == 'cytechlabs/praxis'" in condition
    assert "needs.verify.outputs.publish == 'true'" in condition


def test_publish_job_refuses_a_non_tag_ref():
    publish = _job_block("publish")
    assert "refusing to publish from non-tag ref" in publish


def test_publish_job_refuses_to_overwrite_published_artifacts():
    """A version tag is immutable by policy: neither the GitHub Release nor an
    already published image version may be replaced by a re-run."""
    publish = _job_block("publish")
    assert "check-release-absence.sh release" in publish
    assert "check-release-absence.sh image" in publish
    # The absence checks run before anything is promoted.
    assert publish.index("check-release-absence.sh") < publish.index(
        "scripts/promote-release-images.sh"
    )


def test_registry_tooling_is_installed_before_it_is_used():
    """The image absence check reads the registry through buildx. Invoking it
    before buildx exists turned a tooling failure into 'nothing is there'."""
    publish = _job_block("publish")
    assert publish.index("docker/setup-buildx-action@") < publish.index(
        "check-release-absence.sh"
    )
    assert publish.index("docker/login-action@") < publish.index(
        "check-release-absence.sh"
    )


def test_publish_job_requires_the_matching_agent_release():
    """The index is the whole-product record. Publishing it without the agent
    release it names would ship a knowingly incomplete release."""
    publish = _job_block("publish")
    assert "is not available" in publish
    assert "before releasing the application" in publish
    assert "--agent-checksums" in publish
    # Required before any image is promoted.
    assert publish.index("Require the matching agent release") < publish.index(
        "scripts/promote-release-images.sh"
    )


def test_publish_job_binds_the_agent_tag_to_the_same_commit():
    """Matching version numbers do not establish a shared source commit. A
    stale or independently moved agent tag can carry the right version and
    still point somewhere else, which would put two source states behind one
    whole-product release record."""
    publish = _job_block("publish")
    assert "scripts/check-tag-commit.sh" in publish
    check = publish.split("scripts/check-tag-commit.sh", 1)[1].splitlines()[0]
    assert "$AGENT_TAG" in check
    assert "$COMMIT" in check
    # Checked before the manifest is downloaded and before anything is pushed.
    assert publish.index("scripts/check-tag-commit.sh") < publish.index(
        "gh release download"
    )
    assert publish.index("scripts/check-tag-commit.sh") < publish.index(
        "scripts/promote-release-images.sh"
    )


def test_publish_workflow_pins_every_action_to_a_commit():
    """A tag is mutable; a workflow that holds write tokens and an OIDC
    identity must pin to immutable commits."""
    uses = re.findall(r"uses:\s*(\S+)", _workflow_text())
    assert uses, "workflow declares no actions"
    for ref in uses:
        _, _, version = ref.partition("@")
        assert re.fullmatch(
            r"[0-9a-f]{40}", version
        ), f"{ref} is not pinned to a full commit SHA"


def test_pinned_actions_name_their_upstream_version():
    """A bare 40 character hash is unmaintainable without knowing what it is."""
    for line in _workflow_text().splitlines():
        if "uses:" in line and "@" in line:
            assert re.search(
                r"#\s*v\S+", line
            ), f"pinned action carries no version comment: {line.strip()}"


def test_release_artifacts_are_bound_to_the_verified_commit():
    """Both downstream jobs check out the commit the gate verified, and
    confirm it, rather than resolving the ref a second time."""
    for job in ("build", "publish"):
        body = _job_block(job)
        assert "ref: ${{ needs.verify.outputs.commit }}" in body, job
        assert "expected the verified commit" in body, job


def test_paid_capability_token_is_referenced_once_where_the_image_is_built():
    """The wheel is fetched in the job that builds the image that gets scanned
    and promoted, and only when a paid build was requested. A second reference
    anywhere would mean a second chance to build an unscanned variant."""
    text = _workflow_text()
    assert text.count("PRAXIS_EE_DEPLOY_TOKEN") == 1
    assert "PRAXIS_EE_DEPLOY_TOKEN" in _job_block("build")
    assert "PRAXIS_EE_DEPLOY_TOKEN" not in _job_block("publish")


def test_paid_capability_wheel_is_fetched_only_when_requested():
    """A tag push never asks for the paid variant, so it must never reach the
    private artifact."""
    build = _job_block("build")
    fetch = build.split("Fetch paid capability wheel", 1)[1]
    assert (
        "if: ${{ needs.verify.outputs.praxis_ee == '1' }}" in fetch.split("run:", 1)[0]
    )
    assert "deploy token is not configured" in build


def test_paid_capability_secret_is_never_a_build_argument():
    """A build argument reaches image metadata, provenance, and build logs."""
    for match in re.findall(r"build-args:\s*\|\n((?:\s+\S+\n)+)", _workflow_text()):
        assert "secrets." not in match, f"secret passed as a build argument: {match}"


# ------------------------------------------------------------ package contract


def test_published_package_names_are_the_documented_public_ones():
    """Deployments pin these names. Renaming a package breaks every pull."""
    text = _workflow_text()
    assert f"BACKEND_PACKAGE: {BACKEND_PACKAGE}" in text
    assert f"FRONTEND_PACKAGE: {FRONTEND_PACKAGE}" in text
    assert f"REGISTRY: {REGISTRY}" in text
    assert f"OWNER: {OWNER}" in text


def test_moving_tags_are_limited_to_stable_releases():
    """A prerelease must never take over ``latest`` or the major.minor tag."""
    promotion = PROMOTE.read_text(encoding="utf-8")
    guarded = promotion.split('if [ "${is_stable}" = "true" ]', 1)
    assert len(guarded) == 2, "moving tags are not guarded by the stable check"
    assert ":latest" not in guarded[0], "latest is pushed outside the stable guard"
    assert "major_minor}" not in guarded[0]
    assert ":latest" in guarded[1]
    assert "${major_minor}" in guarded[1]


def test_sboms_are_generated_from_the_published_digest():
    """A tag can be repointed between the push and the scan; a digest cannot.
    The published SBOM has to describe the bytes that were pushed."""
    publish = _job_block("publish")
    for step in ("backend", "frontend"):
        expected = (
            "image-ref: ${{ env.REGISTRY }}/${{ env.OWNER }}/"
            "${{ env.%s_PACKAGE }}@${{ steps.promote.outputs.%s_digest }}"
            % (step.upper(), step)
        )
        assert expected in publish, step


def test_publish_job_attests_provenance_and_sbom_for_both_images():
    publish = _job_block("publish")
    assert publish.count("actions/attest@") == 4
    assert publish.count("push-to-registry: true") == 4


def test_attestations_use_one_maintained_action_in_both_modes():
    """``actions/attest`` supersedes the ``attest-build-provenance`` and
    ``attest-sbom`` wrappers. It picks its mode from the inputs: no
    ``sbom-path`` and no predicate means SLSA build provenance."""
    text = _workflow_text()
    assert "actions/attest-sbom@" not in text
    assert "actions/attest-build-provenance@" not in text

    for step in ("backend", "frontend"):
        provenance = text.split(f"Attest {step} provenance", 1)[1].split("- name:", 1)[
            0
        ]
        assert "actions/attest@" in provenance
        assert "sbom-path" not in provenance, "provenance mode must not pass an SBOM"
        assert (
            "predicate" not in provenance
        ), "provenance mode must not pass a predicate"

        sbom = text.split(f"Attest {step} SBOM", 1)[1].split("- name:", 1)[0]
        assert "actions/attest@" in sbom
        assert f"sbom-path: sbom-{step}-" in sbom


def test_agent_release_is_consumed_not_rebuilt():
    """The agent has its own release contract. This workflow reads its
    published manifest and must not build or sign agent artifacts."""
    text = _workflow_text()
    assert "agent-v${{ needs.verify.outputs.base_version }}" in text
    assert "checksums.txt" in text
    assert "cosign" not in text
    assert "agent/Makefile" not in text


# ------------------------------------------------------------ readiness script


def test_readiness_check_requires_the_release_publication_surface():
    """The readiness gate runs before a tag is cut; it has to know about the
    files the publish path depends on."""
    text = READINESS.read_text(encoding="utf-8")
    assert "docs/ghcr-release-operations.md" in text
    assert "scripts/build_release_index.py" in text
    assert "scripts/check-release-absence.sh" in text
    assert "scripts/check-tag-commit.sh" in text
    assert "scripts/promote-release-images.sh" in text
    assert ".github/workflows/publish.yml" in text


def test_publish_workflow_runs_the_readiness_check_before_building():
    """Package metadata that disagrees with the tag would name every artifact
    for a version that was never released."""
    verify = _job_block("verify")
    assert "scripts/check-release-readiness.sh" in verify
    assert verify.index("check-release-readiness.sh") < verify.index("pytest")


# --------------------------------------------------------------- release index


def _sbom(reference: str, spec_version: str = SPEC_VERSION) -> dict:
    """A CycloneDX document shaped like the scanner's image output."""
    repository, _, digest = reference.partition("@")
    purl = f"pkg:oci/{repository.rsplit('/', 1)[-1]}@{digest or 'sha256:0'}"
    if digest:
        purl += f"?arch=amd64&repository_url={repository.replace('/', '%2F')}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "metadata": {
            "component": {
                "bom-ref": purl,
                "type": "container",
                "name": reference,
                "purl": purl,
            }
        },
        "components": [],
    }


def _write_sbom(tmp_path: Path, name: str, document: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run_index(tmp_path: Path, *args: str):
    return subprocess.run(
        [
            sys.executable,
            str(BUILD_INDEX),
            "--repository",
            "cytechlabs/praxis",
            "--registry",
            REGISTRY,
            "--owner",
            OWNER,
            "--sbom-spec-version",
            SPEC_VERSION,
            "--workflow",
            ".github/workflows/publish.yml",
            "--run-id",
            "12345",
            "--out-json",
            str(tmp_path / "release-index.json"),
            "--out-markdown",
            str(tmp_path / "release-index.md"),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _publish_args(
    tmp_path: Path,
    version: str = "1.0.0",
    digest: str = DIGEST,
    agent: bool = True,
) -> list:
    """The minimum a publish run must supply. Publishing requires the agent
    release manifest, so it is part of the baseline rather than an extra."""
    backend_ref = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}@{digest}"
    frontend_ref = f"{REGISTRY}/{OWNER}/{FRONTEND_PACKAGE}@{digest}"
    backend_sbom = _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(backend_ref))
    frontend_sbom = _write_sbom(tmp_path, "sbom-frontend.cdx.json", _sbom(frontend_ref))
    args = [
        "--mode",
        "publish",
        "--version",
        version,
        "--tag",
        f"v{version}",
        "--commit",
        COMMIT,
        "--attestations",
        "provenance,sbom",
        "--image-ref",
        f"{BACKEND_PACKAGE}={backend_ref}",
        "--image-digest",
        f"{BACKEND_PACKAGE}={digest}",
        "--image-tags",
        f"{BACKEND_PACKAGE}={version},latest",
        "--image-sbom",
        f"{BACKEND_PACKAGE}={backend_sbom}",
        "--image-ref",
        f"{FRONTEND_PACKAGE}={frontend_ref}",
        "--image-digest",
        f"{FRONTEND_PACKAGE}={digest}",
        "--image-tags",
        f"{FRONTEND_PACKAGE}={version},latest",
        "--image-sbom",
        f"{FRONTEND_PACKAGE}={frontend_sbom}",
    ]
    if agent:
        base_version = version.split("-")[0]
        args += [
            "--agent-tag",
            f"agent-v{base_version}",
            "--agent-version",
            f"v{base_version}",
            "--agent-checksums",
            str(_agent_manifest(tmp_path, version=f"v{base_version}")),
        ]
    return args


def _agent_manifest(
    tmp_path: Path, version: str = "v1.0.0", complete: bool = True
) -> Path:
    names = [
        f"praxis-agent-{version}-linux-amd64.tar.gz",
        f"praxis-agent-{version}-linux-arm64.tar.gz",
        f"praxis-agent-{version}-linux-amd64-sbom.cdx.json",
        f"praxis-agent-{version}-linux-arm64-sbom.cdx.json",
    ]
    if not complete:
        names = names[:2]
    path = tmp_path / "checksums.txt"
    path.write_text(
        "".join(f"{'c' * 64}  {name}\n" for name in names), encoding="utf-8"
    )
    return path


def test_index_records_published_images_by_digest(tmp_path):
    result = _run_index(tmp_path, *_publish_args(tmp_path))
    assert result.returncode == 0, result.stderr

    index = json.loads((tmp_path / "release-index.json").read_text(encoding="utf-8"))
    assert index["mode"] == "publish"
    assert index["source"]["commit"] == COMMIT
    assert index["tag"] == "v1.0.0"

    images = {
        c["name"]: c for c in index["components"] if c["kind"] == "container-image"
    }
    assert set(images) == {BACKEND_PACKAGE, FRONTEND_PACKAGE}
    for image in images.values():
        assert image["digest"] == DIGEST
        assert image["pull_by_digest"] == f"{image['repository']}@{DIGEST}"
        assert image["attestations"] == ["provenance", "sbom"]
        assert image["sbom"]["spec_version"] == SPEC_VERSION

    markdown = (tmp_path / "release-index.md").read_text(encoding="utf-8")
    assert DIGEST in markdown
    assert f"docker pull {REGISTRY}/{OWNER}/{BACKEND_PACKAGE}@{DIGEST}" in markdown


def test_index_rejects_a_tag_that_disagrees_with_the_version(tmp_path):
    args = _publish_args(tmp_path)
    args[args.index("--tag") + 1] = "v9.9.9"
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "does not match" in result.stderr


def test_index_rejects_an_abbreviated_commit(tmp_path):
    """How many characters git needs to abbreviate a hash depends on the local
    object count, so a short hash does not identify a source state."""
    args = _publish_args(tmp_path)
    args[args.index("--commit") + 1] = COMMIT[:12]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "40 character commit" in result.stderr


def test_index_rejects_a_published_image_without_a_digest(tmp_path):
    args = _publish_args(tmp_path)
    index = args.index("--image-digest")
    del args[index : index + 2]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "identified by digest" in result.stderr


def test_index_rejects_an_sbom_generated_from_a_different_image(tmp_path):
    """The defect this guards: an SBOM from an earlier build, renamed to look
    like this release's, would be attached and attested as authoritative."""
    args = _publish_args(tmp_path)
    stale = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}@{OTHER_DIGEST}"
    _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(stale))
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "expected the published image" in result.stderr


def test_index_rejects_an_sbom_whose_identifiers_disagree_with_its_name(tmp_path):
    """A document can name the right image while its purl still points at the
    build it was actually generated from."""
    args = _publish_args(tmp_path)
    reference = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}@{DIGEST}"
    document = _sbom(reference)
    document["metadata"]["component"]["purl"] = document["metadata"]["component"][
        "purl"
    ].replace(DIGEST, OTHER_DIGEST)
    _write_sbom(tmp_path, "sbom-backend.cdx.json", document)
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "purl reports" in result.stderr


def test_index_rejects_an_sbom_at_the_wrong_spec_version(tmp_path):
    """The release record states a spec version. A generator change that moved
    it must fail the release rather than make the record wrong."""
    args = _publish_args(tmp_path)
    reference = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}@{DIGEST}"
    _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(reference, spec_version="1.4"))
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "specVersion" in result.stderr


def test_index_rejects_a_missing_sbom(tmp_path):
    args = _publish_args(tmp_path)
    (tmp_path / "sbom-frontend.cdx.json").unlink()
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "does not exist" in result.stderr


def test_index_rejects_an_image_with_no_sbom_at_all(tmp_path):
    args = _publish_args(tmp_path)
    index = args.index(
        f"{FRONTEND_PACKAGE}=" + str(tmp_path / "sbom-frontend.cdx.json")
    )
    del args[index - 1 : index + 1]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "every published image ships an SBOM" in result.stderr


def test_index_rejects_tags_that_omit_the_release_version(tmp_path):
    """``latest`` alone would leave the release with no immutable name."""
    args = _publish_args(tmp_path)
    args[args.index(f"{BACKEND_PACKAGE}=1.0.0,latest")] = f"{BACKEND_PACKAGE}=latest"
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "does not include the release version" in result.stderr


def test_index_requires_attestations_when_publishing(tmp_path):
    args = _publish_args(tmp_path)
    index = args.index("--attestations")
    del args[index : index + 2]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "attestations is required" in result.stderr


def test_validation_run_records_that_nothing_was_published(tmp_path):
    """A dry run has no registry digest. Reporting the local build's hash as
    one would put an unpullable reference in the release record."""
    reference = f"{BACKEND_PACKAGE}:1.0.0-validate"
    sbom = _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(reference))
    result = _run_index(
        tmp_path,
        "--mode",
        "validate",
        "--version",
        "1.0.0",
        "--tag",
        "v1.0.0",
        "--commit",
        COMMIT,
        "--image-ref",
        f"{BACKEND_PACKAGE}={reference}",
        "--image-sbom",
        f"{BACKEND_PACKAGE}={sbom}",
    )
    assert result.returncode == 0, result.stderr

    index = json.loads((tmp_path / "release-index.json").read_text(encoding="utf-8"))
    assert index["mode"] == "validate"
    image = index["components"][0]
    assert image["digest"] is None
    assert image["tags"] == []
    assert image["attestations"] == []

    markdown = (tmp_path / "release-index.md").read_text(encoding="utf-8")
    assert "No image, tag, release, or attestation was" in markdown
    assert "docker pull" not in markdown


def test_validation_run_refuses_to_claim_a_digest(tmp_path):
    reference = f"{BACKEND_PACKAGE}:1.0.0-validate"
    sbom = _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(reference))
    result = _run_index(
        tmp_path,
        "--mode",
        "validate",
        "--version",
        "1.0.0",
        "--tag",
        "v1.0.0",
        "--commit",
        COMMIT,
        "--image-ref",
        f"{BACKEND_PACKAGE}={reference}",
        "--image-digest",
        f"{BACKEND_PACKAGE}={DIGEST}",
        "--image-sbom",
        f"{BACKEND_PACKAGE}={sbom}",
    )
    assert result.returncode != 0
    assert "nothing was" in result.stderr


# ----------------------------------------------------------- agent integration


def test_index_consumes_the_published_agent_manifest(tmp_path):
    result = _run_index(tmp_path, *_publish_args(tmp_path))
    assert result.returncode == 0, result.stderr

    index = json.loads((tmp_path / "release-index.json").read_text(encoding="utf-8"))
    agent = next(c for c in index["components"] if c["kind"] == "release-archive")
    assert agent["status"] == "published"
    assert agent["release_tag"] == "agent-v1.0.0"
    assert len(agent["artifacts"]) == 4
    assert agent["signature"]["manifest"] == "checksums.txt"


def test_index_refuses_to_publish_without_the_agent_manifest(tmp_path):
    """The index is the whole-product release record. Publishing one that
    admits the agent is outstanding is still publishing an incomplete record,
    so the agent release has to exist first."""
    args = _publish_args(tmp_path)
    index = args.index("--agent-checksums")
    del args[index : index + 2]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "publish and verify the agent release" in result.stderr


def test_index_refuses_to_publish_without_naming_an_agent_release(tmp_path):
    args = _publish_args(tmp_path)
    for flag in ("--agent-checksums", "--agent-version", "--agent-tag"):
        index = args.index(flag)
        del args[index : index + 2]
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "agent-tag is required when publishing" in result.stderr


def test_index_rejects_an_incomplete_agent_manifest(tmp_path):
    """A manifest missing an architecture would publish a release record that
    silently ships fewer artifacts than it claims."""
    args = _publish_args(tmp_path)
    _agent_manifest(tmp_path, complete=False)
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "incomplete" in result.stderr


def test_index_rejects_an_agent_manifest_from_another_version(tmp_path):
    """Consuming the previous release's manifest would attach last version's
    checksums to this release."""
    args = _publish_args(tmp_path)
    _agent_manifest(tmp_path, version="v0.9.0")
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "incomplete" in result.stderr


def test_validation_index_may_record_an_unpublished_agent_as_pending(tmp_path):
    """A dry run records nothing permanently, so it may describe an agent
    release that has not been cut yet rather than refusing to run."""
    reference = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    sbom = _write_sbom(tmp_path, "sbom-backend.cdx.json", _sbom(reference))
    result = _run_index(
        tmp_path,
        "--mode",
        "validate",
        "--version",
        "1.0.0",
        "--tag",
        "v1.0.0",
        "--commit",
        COMMIT,
        "--image-ref",
        f"{BACKEND_PACKAGE}={reference}",
        "--image-sbom",
        f"{BACKEND_PACKAGE}={sbom}",
        "--agent-tag",
        "agent-v1.0.0",
        "--agent-version",
        "v1.0.0",
    )
    assert result.returncode == 0, result.stderr

    index = json.loads((tmp_path / "release-index.json").read_text(encoding="utf-8"))
    agent = next(c for c in index["components"] if c["kind"] == "release-archive")
    assert agent["status"] == "pending"
    assert agent["artifacts"] == []

    markdown = (tmp_path / "release-index.md").read_text(encoding="utf-8")
    assert "was not published" in markdown


def test_index_rejects_an_agent_tag_that_disagrees_with_its_version(tmp_path):
    args = _publish_args(tmp_path)
    args[args.index("agent-v1.0.0")] = "agent-v0.9.0"
    result = _run_index(tmp_path, *args)
    assert result.returncode != 0
    assert "does not match agent release" in result.stderr


# ------------------------------------------------------------------- hygiene


def test_index_publishes_no_local_paths(tmp_path):
    """The index is public. Runner and workspace paths are not."""
    result = _run_index(tmp_path, *_publish_args(tmp_path))
    assert result.returncode == 0, result.stderr

    for name in ("release-index.json", "release-index.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert str(tmp_path) not in text, f"{name} leaks the working directory"
        assert "praxis-ee" not in text, f"{name} names a private artifact"
        assert "sbom-backend.cdx.json" in text


def test_index_requires_report_links_rather_than_report_contents(tmp_path):
    """Large scanner output is linked, so a malformed local path cannot be
    smuggled into the public record as a report location."""
    result = _run_index(
        tmp_path,
        *_publish_args(tmp_path),
        "--report",
        "scan reports=/home/runner/work/praxis/trivy.sarif",
    )
    assert result.returncode != 0
    assert "https URL" in result.stderr


# ------------------------------------------------------- absence check (closed)


def _stub(directory: Path, name: str, body: str) -> None:
    """Put a fake `gh` or `docker` on PATH so each answer can be replayed."""
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _run_absence(stub_dir: Path, *args: str):
    return subprocess.run(
        ["bash", str(ABSENCE), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": f"{stub_dir}:/usr/bin:/bin",
            "HOME": str(stub_dir),
        },
    )


NOT_FOUND_GH = 'echo "gh: Not Found (HTTP 404)" >&2; exit 1'
FOUND_GH = 'echo "{\\"tag_name\\": \\"v1.0.0\\"}"; exit 0'


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_allows_publication_when_the_release_is_missing(tmp_path):
    _stub(tmp_path, "gh", NOT_FOUND_GH)
    result = _run_absence(tmp_path, "release", "cytechlabs/praxis", "v1.0.0")
    assert result.returncode == 0, result.stderr
    assert "no release v1.0.0 exists" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_refuses_when_the_release_exists(tmp_path):
    _stub(tmp_path, "gh", FOUND_GH)
    result = _run_absence(tmp_path, "release", "cytechlabs/praxis", "v1.0.0")
    assert result.returncode != 0
    assert "already exists" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "failure",
    [
        'echo "error connecting to api.github.com" >&2; exit 1',
        'echo "gh: Bad credentials (HTTP 401)" >&2; exit 1',
        'echo "gh: API rate limit exceeded (HTTP 403)" >&2; exit 1',
        'echo "gh: Server Error (HTTP 500)" >&2; exit 1',
        "exit 127",
    ],
)
def test_absence_check_fails_closed_on_an_operational_error(tmp_path, failure):
    """The defect this guards: treating any failure as "not found" means an
    expired token or a network blip silently authorises an overwrite."""
    _stub(tmp_path, "gh", failure)
    result = _run_absence(tmp_path, "release", "cytechlabs/praxis", "v1.0.0")
    assert result.returncode != 0
    assert "could not determine" in result.stderr
    assert "already exists" not in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_allows_publication_when_the_image_tag_is_missing(tmp_path):
    _stub(
        tmp_path,
        "docker",
        'echo "ERROR: ghcr.io/cytechlabs/praxis-backend:1.0.0: not found" >&2; exit 1',
    )
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode == 0, result.stderr
    assert "no image" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_refuses_when_the_image_version_exists(tmp_path):
    _stub(
        tmp_path,
        "docker",
        'echo "Name: ghcr.io/cytechlabs/praxis-backend:1.0.0"; exit 0',
    )
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode != 0
    assert "already exists" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_allows_the_first_publish_of_a_new_package(tmp_path):
    """A package that has never been published cannot be described by the
    registry at all, and its refusal looks like an authorization failure. Only
    GitHub confirming the package does not exist resolves that."""
    _stub(
        tmp_path,
        "docker",
        'echo "ERROR: failed to authorize: 403 Forbidden" >&2; exit 1',
    )
    _stub(tmp_path, "gh", NOT_FOUND_GH)
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode == 0, result.stderr
    assert "has never been published" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "package_answer",
    [
        'echo "{\\"name\\": \\"praxis-backend\\"}"; exit 0',  # package does exist
        'echo "gh: Bad credentials (HTTP 401)" >&2; exit 1',  # cannot tell
    ],
)
def test_absence_check_fails_closed_when_the_registry_will_not_answer(
    tmp_path, package_answer
):
    """A registry authorization failure is not evidence of absence."""
    _stub(
        tmp_path,
        "docker",
        'echo "ERROR: failed to authorize: 403 Forbidden" >&2; exit 1',
    )
    _stub(tmp_path, "gh", package_answer)
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode != 0
    assert "could not determine" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_fails_closed_when_the_registry_client_is_absent(tmp_path):
    """Ask an uninstalled tool whether something exists and it will not say
    no; it will fail, which is not the same answer."""
    _stub(tmp_path, "gh", NOT_FOUND_GH)
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode != 0
    assert "docker is not installed" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_fails_closed_when_the_github_client_is_absent(tmp_path):
    """The registry could not answer and the fallback cannot run either, so
    nothing here establishes that the package is free."""
    _stub(
        tmp_path,
        "docker",
        'echo "ERROR: failed to authorize: 403 Forbidden" >&2; exit 1',
    )
    result = _run_absence(
        tmp_path, "image", f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}:1.0.0"
    )
    assert result.returncode != 0
    assert "gh is not installed" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_absence_check_rejects_a_malformed_image_reference(tmp_path):
    _stub(tmp_path, "docker", "exit 0")
    result = _run_absence(tmp_path, "image", "praxis-backend:1.0.0")
    assert result.returncode != 0
    assert "expected" in result.stderr


# ------------------------------------------------------------ promotion output


# What `docker push` actually prints. The last line is the trap: it ends in a
# digest, so any of this reaching the helper's stdout looks digest-shaped to a
# caller that only greps.
PUSH_OUTPUT = """echo "The push refers to repository [${2%:*}]"
echo "b2d5eeeaba3a: Preparing"
echo "5f70bf18a086: Layer already exists"
echo "b2d5eeeaba3a: Pushed"
echo "${2##*:}: digest: sha256:cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe size: 2402\""""

PUSHED_DIGEST = "sha256:" + "cafebabe" * 8


def _docker_stub(
    tmp_path: Path,
    repo_digests: str = f"ghcr.io/cytechlabs/praxis-backend@{PUSHED_DIGEST}",
    push_status: int = 0,
) -> Path:
    """A `docker` that talks like the real one: chatty pushes, quiet inspects."""
    log = tmp_path / "pushed.txt"
    _stub(
        tmp_path,
        "docker",
        f"""
case "$1" in
  push)
    {PUSH_OUTPUT}
    echo "$2" >> {log}
    exit {push_status}
    ;;
  tag) exit 0 ;;
  image) printf '%b\\n' "{repo_digests}"; exit 0 ;;
esac
exit 0
""".strip(),
    )
    return log


def _run_promote(stub_dir: Path, *args: str):
    return subprocess.run(
        ["bash", str(PROMOTE), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "HOME": str(stub_dir)},
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_reports_only_the_digest_on_stdout(tmp_path):
    """The regression this exists for: the caller captures stdout into a
    single-line workflow output. If push progress shares that channel, the
    digest variable silently becomes a transcript that still contains something
    digest-shaped, so asserting "a digest appears somewhere" would not catch
    it. The whole of stdout has to be the digest and nothing else."""
    _docker_stub(tmp_path)
    result = _run_promote(
        tmp_path, f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}", "1.0.0", "true", "1.0"
    )
    assert result.returncode == 0, result.stderr

    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}", result.stdout.strip()
    ), f"stdout is not exactly one digest: {result.stdout!r}"
    assert result.stdout.strip() == PUSHED_DIGEST
    # The progress was not discarded, just routed away from the digest channel.
    assert "The push refers to repository" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_pushes_moving_tags_only_for_a_stable_release(tmp_path):
    log = _docker_stub(tmp_path)
    repository = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}"

    result = _run_promote(tmp_path, repository, "1.0.0-rc.1", "false", "")
    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8").split() == [f"{repository}:1.0.0-rc.1"]

    log.unlink()
    result = _run_promote(tmp_path, repository, "1.0.0", "true", "1.0")
    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8").split() == [
        f"{repository}:1.0.0",
        f"{repository}:1.0",
        f"{repository}:latest",
    ]


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_refuses_an_ambiguous_digest(tmp_path):
    """Two digests for one repository means the daemon holds a stale record;
    picking either one would put a guess in the release record."""
    repository = f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}"
    _docker_stub(
        tmp_path,
        repo_digests=f"{repository}@{PUSHED_DIGEST}\\n{repository}@{DIGEST}",
    )
    result = _run_promote(tmp_path, repository, "1.0.0", "false", "")
    assert result.returncode != 0
    assert "exactly one digest" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_refuses_when_no_digest_was_recorded(tmp_path):
    _docker_stub(tmp_path, repo_digests="")
    result = _run_promote(
        tmp_path, f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}", "1.0.0", "false", ""
    )
    assert result.returncode != 0
    assert "exactly one digest" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_fails_when_the_push_fails(tmp_path):
    _docker_stub(tmp_path, push_status=1)
    result = _run_promote(
        tmp_path, f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}", "1.0.0", "false", ""
    )
    assert result.returncode != 0
    assert not re.fullmatch(r"sha256:[0-9a-f]{64}", result.stdout.strip())


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_requires_a_major_minor_for_a_stable_release(tmp_path):
    _docker_stub(tmp_path)
    result = _run_promote(
        tmp_path, f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}", "1.0.0", "true", ""
    )
    assert result.returncode != 0
    assert "major.minor" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_promotion_fails_closed_without_docker(tmp_path):
    result = _run_promote(
        tmp_path, f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}", "1.0.0", "false", ""
    )
    assert result.returncode != 0
    assert "docker is not installed" in result.stderr


# ---------------------------------------------------------- tag commit binding


LIGHTWEIGHT_COMMIT = COMMIT
ANNOTATED_TAG_OBJECT = "b" * 40


def _gh_tag_stub(
    tmp_path: Path,
    ref_answer: str,
    tag_answer: str = "",
    ref_status: int = 0,
    tag_status: int = 0,
) -> None:
    """A `gh` that answers the two calls a tag resolution makes.

    The ref endpoint yields `<sha> <type>`; for an annotated tag the tag-object
    endpoint then yields the commit it points at."""
    _stub(
        tmp_path,
        "gh",
        f"""
for arg in "$@"; do
  case "$arg" in
    */git/ref/tags/*) printf '%s\\n' "{ref_answer}"; exit {ref_status} ;;
    */git/tags/*)     printf '%s\\n' "{tag_answer}"; exit {tag_status} ;;
  esac
done
echo "unexpected invocation: $*" >&2
exit 1
""".strip(),
    )


def _run_tag_check(stub_dir: Path, tag: str = "agent-v1.0.0", expected: str = COMMIT):
    return subprocess.run(
        ["bash", str(TAG_COMMIT), "cytechlabs/praxis", tag, expected],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "HOME": str(stub_dir)},
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_accepts_a_matching_lightweight_tag(tmp_path):
    _gh_tag_stub(tmp_path, f"{LIGHTWEIGHT_COMMIT} commit")
    result = _run_tag_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "resolves to" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_accepts_a_matching_annotated_tag(tmp_path):
    """An annotated tag's ref names a tag object, not a commit. Comparing the
    ref's sha directly would reject every annotated release tag."""
    _gh_tag_stub(tmp_path, f"{ANNOTATED_TAG_OBJECT} tag", tag_answer=COMMIT)
    result = _run_tag_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert COMMIT in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_rejects_a_tag_cut_from_another_commit(tmp_path):
    """The defect this guards: an agent tag with the right version but an
    older commit would enter a release index claiming one source commit."""
    _gh_tag_stub(tmp_path, f"{'c' * 40} commit")
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "was not cut from" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_rejects_an_annotated_tag_peeling_elsewhere(tmp_path):
    _gh_tag_stub(tmp_path, f"{ANNOTATED_TAG_OBJECT} tag", tag_answer="d" * 40)
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "was not cut from" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_fails_closed_on_a_missing_tag(tmp_path):
    _gh_tag_stub(tmp_path, "gh: Not Found (HTTP 404)", ref_status=1)
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "does not exist" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "failure",
    [
        "error connecting to api.github.com",
        "gh: Bad credentials (HTTP 401)",
        "gh: Server Error (HTTP 500)",
    ],
)
def test_tag_check_fails_closed_on_a_resolution_error(tmp_path, failure):
    _gh_tag_stub(tmp_path, failure, ref_status=1)
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "could not resolve" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_fails_closed_when_an_annotated_tag_cannot_be_peeled(tmp_path):
    _gh_tag_stub(
        tmp_path,
        f"{ANNOTATED_TAG_OBJECT} tag",
        tag_answer="gh: Server Error (HTTP 500)",
        tag_status=1,
    )
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "could not peel" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_rejects_an_unsupported_object_type(tmp_path):
    """A tag pointing at a tree or blob resolves to something that is not a
    source state at all."""
    _gh_tag_stub(tmp_path, f"{'e' * 40} tree")
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "unsupported object type" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_fails_closed_without_the_github_client(tmp_path):
    result = _run_tag_check(tmp_path)
    assert result.returncode != 0
    assert "gh is not installed" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_tag_check_rejects_an_abbreviated_expected_commit(tmp_path):
    _gh_tag_stub(tmp_path, f"{COMMIT} commit")
    result = _run_tag_check(tmp_path, expected=COMMIT[:12])
    assert result.returncode != 0
    assert "40 character sha" in result.stderr


def test_publish_workflow_uses_the_shared_absence_check(tmp_path):
    """Keeping the classification in one tested script is what stops the
    workflow from re-growing an untested `|| true`."""
    publish = _job_block("publish")
    assert "|| true" not in publish
    assert publish.count("scripts/check-release-absence.sh") == 2


def test_runbook_documents_the_operator_surface():
    """The runbook is the only place a new operator learns the GHCR specifics
    the workflow assumes."""
    text = GHCR_RUNBOOK.read_text(encoding="utf-8")
    for expected in (
        f"{REGISTRY}/{OWNER}/{BACKEND_PACKAGE}",
        f"{REGISTRY}/{OWNER}/{FRONTEND_PACKAGE}",
        "GITHUB_TOKEN",
        "gh attestation verify",
        "docker buildx imagetools inspect",
        "package visibility",
    ):
        assert expected in text, f"runbook does not cover {expected!r}"


@pytest.mark.parametrize(
    "path",
    [
        PUBLISH_WORKFLOW,
        BUILD_INDEX,
        GHCR_RUNBOOK,
    ],
)
def test_release_surface_stays_ascii(path):
    """These files are copied into terminals, release bodies, and runbooks."""
    text = path.read_text(encoding="utf-8")
    offending = sorted({ch for ch in text if ord(ch) > 127})
    assert not offending, f"{path.name} contains non-ASCII characters {offending}"
