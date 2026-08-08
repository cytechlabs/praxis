"""PRA-389: the agent release contract.

The agent ships as a signed, checksummed tarball built by
``.github/workflows/agent-release.yml`` and consumed by the control plane's
``/agent/download`` routes. Several independent files have to agree for that
to work, and a disagreement is only visible at release time unless something
checks it earlier. These tests are that check.

They cover four things:

- **One version source.** ``agent/VERSION`` is the source of truth. The
  backend mirrors it because the deployed image does not ship the agent
  source tree, so the mirror is asserted rather than assumed.
- **Immutable release selection.** The pinned version may be overridden by
  an operator, but only with an exact version. Moving references such as
  ``latest`` would let the artifact behind a verified checksum change.
- **A publication path that cannot fire by accident.** The release workflow
  must keep a read-only build job, refuse to publish from a fork, and pin
  its actions by commit.
- **A working uninstaller.** ``uninstall.sh`` runs as root and deletes
  files, so it is driven here with hostile input in ``--dry-run``.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api.routes import agent_bootstrap

REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_DIR = REPO_ROOT / "agent"
VERSION_FILE = AGENT_DIR / "VERSION"
GO_VERSION_FILE = AGENT_DIR / "GO_VERSION"
MAKEFILE = AGENT_DIR / "Makefile"
DOCKERFILE_DEV = AGENT_DIR / "Dockerfile.dev"
VERIFY_SBOM = AGENT_DIR / "scripts" / "verify_sbom.py"
UNINSTALL_SH = AGENT_DIR / "packaging" / "uninstall.sh"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "agent-release.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

if sys.platform != "linux":  # pragma: no cover - agent packaging is Linux-only
    pytest.skip("agent packaging is Linux-only", allow_module_level=True)


def _agent_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def _go_version() -> str:
    return GO_VERSION_FILE.read_text(encoding="utf-8").strip()


def _workflow_text() -> str:
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def _job_block(name: str) -> str:
    """Return the body of one job from the release workflow.

    The backend image carries no YAML parser, so the workflow is read as
    text and sliced on indentation: a job body is every line indented
    deeper than the ``  <name>:`` header that opens it."""
    lines = _workflow_text().splitlines()
    header = f"  {name}:"
    try:
        start = lines.index(header)
    except ValueError:  # pragma: no cover - guarded by the assertion below
        raise AssertionError(f"job {name!r} not found in {RELEASE_WORKFLOW}") from None
    body = []
    for line in lines[start + 1 :]:
        if line.strip() and not line.startswith("    "):
            break
        body.append(line)
    return "\n".join(body)


def _permissions(job: str) -> list:
    """Return the entries of a job's ``permissions:`` mapping.

    Job keys sit at four spaces and their children deeper, so the block
    ends at the first non-blank line that is not indented further."""
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


# --------------------------------------------------------------- version source


def test_agent_version_file_is_a_bare_semver():
    """The file holds ``X.Y.Z`` with no ``v``. The ``v`` prefix belongs to
    the tag and the artifact names, which derive it from here."""
    version = _agent_version()
    assert re.fullmatch(
        r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", version
    ), f"agent/VERSION should be a bare X.Y.Z semver, got {version!r}"


def test_backend_default_release_version_mirrors_the_agent_version_file():
    """The backend cannot read agent/VERSION at runtime (the image is built
    from backend/ alone), so it carries a mirror. Drift would make the
    control plane serve a release that was never built."""
    assert agent_bootstrap._DEFAULT_RELEASE_VERSION == f"v{_agent_version()}"


def test_agent_version_matches_the_application_version():
    """The release runbook cuts ``vX.Y.Z`` and ``agent-vX.Y.Z`` from one
    commit sharing one ``X.Y.Z``."""
    root_package = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    assert root_package["version"] == _agent_version()


# ------------------------------------------------------- release version pinning


def test_release_version_defaults_to_the_pinned_version(monkeypatch):
    monkeypatch.delenv("PRAXIS_AGENT_RELEASE_VERSION", raising=False)
    assert agent_bootstrap._release_version() == f"v{_agent_version()}"


def test_release_version_accepts_an_exact_override(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_RELEASE_VERSION", "v1.2.3")
    assert agent_bootstrap._release_version() == "v1.2.3"
    assert agent_bootstrap._release_tag() == "agent-v1.2.3"
    assert agent_bootstrap._gh_release_base().endswith(
        "/cytechlabs/praxis/releases/download/agent-v1.2.3"
    )
    assert (
        agent_bootstrap._real_tarball_name("arm64")
        == "praxis-agent-v1.2.3-linux-arm64.tar.gz"
    )


def test_release_version_accepts_a_prerelease_override(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_RELEASE_VERSION", "v1.0.0-rc1")
    assert agent_bootstrap._release_version() == "v1.0.0-rc1"


def test_release_version_tolerates_surrounding_whitespace(monkeypatch):
    """Env values picked up from a compose file or .env often carry a
    trailing newline; that alone should not disable downloads."""
    monkeypatch.setenv("PRAXIS_AGENT_RELEASE_VERSION", "  v1.2.3\n")
    assert agent_bootstrap._release_version() == "v1.2.3"


@pytest.mark.parametrize(
    "value",
    [
        "latest",  # moving reference
        "main",  # branch
        "v1.0",  # not a full version
        "1.0.0",  # missing the v prefix the tag uses
        "v1.0.0/../../etc/passwd",  # path escape
        "v1.0.0\nlatest",  # smuggled second value
        "v01.0.0",  # leading zero is not a valid semver component
        "https://evil.example.com/x",
    ],
)
def test_release_version_rejects_anything_but_an_exact_version(monkeypatch, value):
    """A moving or malformed pin must disable downloads rather than quietly
    resolve to something else."""
    monkeypatch.setenv("PRAXIS_AGENT_RELEASE_VERSION", value)
    with pytest.raises(HTTPException) as excinfo:
        agent_bootstrap._release_version()
    assert excinfo.value.status_code == 500


# ------------------------------------------------------------- release workflow


def test_release_workflow_triggers_only_on_agent_tags():
    """App releases are tagged ``vX.Y.Z``. The agent workflow must not fire
    on those, or an app release would publish agent artifacts."""
    text = _workflow_text()
    assert "      - 'agent-v*'" in text
    tag_patterns = re.findall(r"^\s+- '(v?[^']*\*[^']*)'", text, re.MULTILINE)
    assert tag_patterns == ["agent-v*"]


def test_release_workflow_exposes_a_dry_run_that_defaults_to_true():
    """A manual run must not publish unless the operator asks for it."""
    text = _workflow_text()
    assert "workflow_dispatch:" in text
    dispatch = text.split("workflow_dispatch:", 1)[1].split("\njobs:", 1)[0]
    assert "dry_run:" in dispatch
    assert "type: boolean" in dispatch
    assert "default: true" in dispatch


def test_release_workflow_defaults_to_no_permissions():
    assert re.search(r"^permissions: \{\}$", _workflow_text(), re.MULTILINE)


def test_build_job_token_is_read_only():
    """The build job runs the Go toolchain and downloads modules. It must
    not be able to write to the repository."""
    assert _permissions(_job_block("build")) == ["contents: read"]


def test_publish_job_holds_only_release_and_signing_permissions():
    assert sorted(_permissions(_job_block("publish"))) == [
        "contents: write",
        "id-token: write",
    ]


def test_publish_job_is_gated_on_the_upstream_repository_and_publish_mode():
    """Prevents a fork, or a dry run, from reaching the signing step."""
    publish = _job_block("publish")
    condition = publish.split("if:", 1)[1].split("runs-on:", 1)[0]
    assert "github.repository == 'cytechlabs/praxis'" in condition
    assert "needs.build.outputs.publish == 'true'" in condition


def test_release_workflow_pins_every_action_to_a_commit():
    """A tag is mutable; a release workflow that holds a write token and an
    OIDC identity must pin to immutable commits."""
    uses = re.findall(r"uses:\s*(\S+)", _workflow_text())
    assert uses, "workflow declares no actions"
    for ref in uses:
        _, _, version = ref.partition("@")
        assert re.fullmatch(
            r"[0-9a-f]{40}", version
        ), f"{ref} is not pinned to a full commit SHA"


def test_published_asset_names_match_what_the_control_plane_requests():
    """The backend translates canonical download names into real release
    asset names. If the workflow renames an asset, that translation breaks."""
    text = _workflow_text()
    version = f"v{_agent_version()}"
    for arch in ("amd64", "arm64"):
        expected = agent_bootstrap._real_tarball_name(arch)
        assert expected == f"praxis-agent-{version}-linux-{arch}.tar.gz"
        # The workflow names assets with the version expression, not a literal.
        assert f"-linux-{arch}.tar.gz" in text
    assert "checksums.txt" in text


def test_release_paths_carry_no_stale_or_mutable_download_references():
    """The published download path must be an exact tag under the project
    org. Personal namespaces and ``releases/latest`` are both regressions."""
    sources = [
        RELEASE_WORKFLOW,
        REPO_ROOT / "backend" / "app" / "api" / "routes" / "agent_bootstrap.py",
        REPO_ROOT / "backend" / "app" / "api" / "routes" / "_assets" / "bootstrap.sh",
        AGENT_DIR / "packaging" / "install.sh",
        UNINSTALL_SH,
    ]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "releases/latest" not in text, f"{path} uses a moving release URL"
        assert "cfreeman29" not in text, f"{path} references a personal namespace"
        for match in re.findall(r"github\.com/([A-Za-z0-9_.-]+)/praxis", text):
            assert match == "cytechlabs", f"{path} points at the {match} namespace"


# ---------------------------------------------------------------- uninstaller


def _run_uninstall(args):
    return subprocess.run(
        ["bash", str(UNINSTALL_SH), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_uninstaller_never_evaluates_a_shell_string():
    """Same invariant the installer holds: values reach commands as argv,
    never as text a shell parses."""
    assert not re.search(r"\beval\b", UNINSTALL_SH.read_text(encoding="utf-8"))


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_uninstaller_dry_run_changes_nothing_and_needs_no_root(tmp_path):
    config_dir = tmp_path / "etc" / "praxis-agent"
    config_dir.mkdir(parents=True)
    identity = config_dir / "agent.key"
    identity.write_text("private", encoding="utf-8")
    binary = tmp_path / "praxis-agent"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    result = _run_uninstall(
        [
            "--dry-run",
            "--no-systemd",
            "--config-dir",
            str(config_dir),
            "--bin-path",
            str(binary),
        ]
    )

    assert result.returncode == 0, result.stderr
    assert "DRY-RUN" in result.stdout
    assert identity.exists()
    assert binary.exists()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_uninstaller_preserves_identity_material_without_purge(tmp_path):
    config_dir = tmp_path / "praxis-agent"
    config_dir.mkdir()
    result = _run_uninstall(
        ["--dry-run", "--no-systemd", "--config-dir", str(config_dir)]
    )
    assert result.returncode == 0, result.stderr
    assert "preserving" in result.stdout
    assert "--purge" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_uninstaller_purge_targets_only_the_requested_directory(tmp_path):
    config_dir = tmp_path / "praxis-agent"
    config_dir.mkdir()
    result = _run_uninstall(
        ["--dry-run", "--no-systemd", "--purge", "--config-dir", str(config_dir)]
    )
    assert result.returncode == 0, result.stderr
    assert f"rm -rf -- {config_dir}" in result.stdout.replace("'", "")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "config_dir",
    ["/", "/etc", "/etc/", "/usr", "/var", "relative/path", "/tmp"],
)
def test_uninstaller_refuses_to_purge_a_system_directory(config_dir):
    """--purge deletes a tree as root. A mistyped or injected path must not
    be able to take out the host."""
    result = _run_uninstall(
        ["--dry-run", "--no-systemd", "--purge", "--config-dir", config_dir]
    )
    assert result.returncode != 0
    assert "refusing to purge" in result.stderr or "absolute path" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "name",
    ["../../etc/passwd", "-x", "a b", "praxis;touch /tmp/pwned", "praxis$(id)"],
)
def test_uninstaller_rejects_an_unsafe_service_name(name):
    """The name becomes both a unit path and a systemctl argument."""
    result = _run_uninstall(["--dry-run", "--service-name", name])
    assert result.returncode != 0
    assert "service-name" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_uninstaller_does_not_execute_injected_shell_syntax(tmp_path):
    """A path carrying shell metacharacters is shown quoted, not run."""
    marker = tmp_path / "pwned"
    hostile = f"{tmp_path}/praxis-agent; touch {marker}"

    result = _run_uninstall(["--dry-run", "--no-systemd", "--bin-path", hostile])

    assert result.returncode == 0, result.stderr
    assert not marker.exists()


# ------------------------------------------------------------ go toolchain pin


def test_go_version_file_pins_an_exact_patch_release():
    """A minor-version pin such as "1.26" lets a later patch release change
    the binary produced from identical source."""
    version = _go_version()
    assert re.fullmatch(
        r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", version
    ), f"agent/GO_VERSION should be an exact X.Y.Z patch version, got {version!r}"


def test_dev_image_pins_the_same_go_version():
    """The dev image is the local release builder, so its toolchain has to be
    the one the release workflow uses."""
    text = DOCKERFILE_DEV.read_text(encoding="utf-8")
    declared = re.search(r"^ARG GO_VERSION=(\S+)$", text, re.MULTILINE)
    assert declared, "Dockerfile.dev declares no GO_VERSION build argument"
    assert declared.group(1) == _go_version()


def test_dev_image_base_is_digest_pinned():
    """A tag can be repointed at a new image. The digest cannot, so the
    builder base is an immutable input."""
    text = DOCKERFILE_DEV.read_text(encoding="utf-8")
    from_line = re.search(r"^FROM\s+(\S+)$", text, re.MULTILINE)
    assert from_line, "Dockerfile.dev has no FROM line"
    reference = from_line.group(1)
    assert reference.startswith(
        "golang:${GO_VERSION}-alpine@sha256:"
    ), f"builder base should be the GO_VERSION alpine image pinned by digest, got {reference}"
    digest = reference.split("@sha256:", 1)[1]
    assert re.fullmatch(r"[0-9a-f]{64}", digest), f"malformed image digest {digest!r}"


def test_release_workflow_builds_with_the_pinned_toolchain():
    """setup-go resolving from go.mod would accept any 1.26 patch release."""
    text = _workflow_text()
    assert "agent/GO_VERSION" in text
    assert (
        "go-version-file" not in text
    ), "release build must not resolve Go from go.mod"
    assert "go-version: ${{ steps.go.outputs.version }}" in text
    assert "check-latest: false" in text
    # The workflow asserts the resolved toolchain rather than trusting setup-go.
    assert "go env GOVERSION" in text


def test_agent_ci_lane_uses_the_same_pinned_toolchain():
    """A drift between the PR lane and the release lane would mean CI never
    exercises the toolchain that actually ships."""
    agent_lane = CI_WORKFLOW.read_text(encoding="utf-8").split("  agent-build:", 1)
    assert len(agent_lane) == 2, "ci.yml has no agent-build job"
    lane = agent_lane[1].split("\n  frontend-checks:", 1)[0]
    assert "GO_VERSION" in lane
    assert "go-version: ${{ steps.go.outputs.version }}" in lane
    assert "go-version-file" not in lane


def test_makefile_derives_the_toolchain_from_the_pin():
    """GOTOOLCHAIN makes the go command use exactly this release rather than
    whatever version happens to be installed."""
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "GO_VERSION_FILE := GO_VERSION" in text
    assert "export GOTOOLCHAIN := go$(GO_VERSION)" in text


# --------------------------------------------------------- commit identity


def test_release_inputs_stamp_the_full_commit_sha():
    """How many characters git needs to abbreviate a hash depends on the
    local object count, so a short hash is not a reproducible identifier."""
    for path in (MAKEFILE, CI_WORKFLOW):
        text = path.read_text(encoding="utf-8")
        assert (
            "rev-parse --short" not in text
        ), f"{path} abbreviates the commit; stamp the full SHA"
    assert "git rev-parse HEAD" in MAKEFILE.read_text(encoding="utf-8")


# ----------------------------------------------------------------- sbom


def _valid_sbom(version: str, goarch: str = "amd64") -> dict:
    """A minimal SBOM shaped like the generator's output."""
    name = "github.com/cytechlabs/praxis/agent"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:golang/{name}@{version}?type=module#cmd/praxis-agent",
                "type": "application",
                "name": name,
                "version": version,
                "purl": (
                    f"pkg:golang/{name}@{version}"
                    f"?goarch={goarch}&goos=linux&type=module#cmd/praxis-agent"
                ),
            }
        },
        "components": [],
    }


def _run_verify_sbom(document, tmp_path, version="v1.0.0", goarch="amd64"):
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(VERIFY_SBOM),
            "--sbom",
            str(sbom),
            "--version",
            version,
            "--spec-version",
            "1.5",
            "--goarch",
            goarch,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_sbom_verifier_accepts_a_correct_document(tmp_path):
    result = _run_verify_sbom(_valid_sbom("v1.0.0"), tmp_path)
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_sbom_verifier_rejects_a_go_pseudo_version(tmp_path):
    """The defect this guards: the generator defaults the primary component
    to a pseudo-version derived from git history."""
    pseudo = "v0.0.0-20260808170442-00fdd4df026d"
    result = _run_verify_sbom(_valid_sbom(pseudo), tmp_path)
    assert result.returncode != 0
    assert "version" in result.stderr


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda d: d["metadata"]["component"].update(version="v9.9.9"), "version"),
        (lambda d: d.update(specVersion="1.6"), "specVersion"),
        (lambda d: d.update(bomFormat="SPDX"), "bomFormat"),
        (lambda d: d["metadata"]["component"].update(name="example.com/other"), "name"),
        (lambda d: d["metadata"]["component"].update(type="library"), "type"),
        (lambda d: d.update(serialNumber="urn:uuid:1"), "serialNumber"),
        (lambda d: d["metadata"].update(timestamp="2026-08-08T00:00:00Z"), "timestamp"),
        (lambda d: d["metadata"].pop("component"), "metadata.component"),
    ],
)
def test_sbom_verifier_rejects_a_broken_document(tmp_path, mutate, expected):
    document = _valid_sbom("v1.0.0")
    mutate(document)
    result = _run_verify_sbom(document, tmp_path)
    assert result.returncode != 0
    assert expected in result.stderr


def test_sbom_verifier_catches_identifiers_that_disagree_with_the_version(tmp_path):
    """The version can be right while purl or bom-ref still carries the
    generator's default, which would make the SBOM disagree with itself."""
    for field in ("purl", "bom-ref"):
        document = _valid_sbom("v1.0.0")
        document["metadata"]["component"][field] = document["metadata"]["component"][
            field
        ].replace("@v1.0.0", "@v0.0.0-20260808170442-00fdd4df026d")
        result = _run_verify_sbom(document, tmp_path)
        assert result.returncode != 0, f"{field} mismatch was accepted"
        assert field in result.stderr


def test_sbom_verifier_catches_the_wrong_architecture(tmp_path):
    """Regression for a real defect: the generator takes the architecture
    from the environment, so both SBOMs claimed the host's."""
    result = _run_verify_sbom(
        _valid_sbom("v1.0.0", goarch="amd64"), tmp_path, goarch="arm64"
    )
    assert result.returncode != 0
    assert "goarch" in result.stderr


def test_release_builds_one_sbom_per_published_binary():
    """The dependency set is resolved per GOOS/GOARCH, so one module-level
    SBOM would not describe either tarball accurately."""
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert (
        "-version $(VERSION)" in makefile
    ), "SBOM must be stamped with the release version"
    assert "-output-version $(SBOM_SPEC_VERSION)" in makefile
    assert "GOOS=linux GOARCH=$$arch" in makefile
    assert "release: package sbom verify-sbom checksums" in makefile

    workflow = _workflow_text()
    for arch in ("amd64", "arm64"):
        assert f"-linux-{arch}-sbom.cdx.json" in workflow
