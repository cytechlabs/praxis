"""PRA-426: release readiness covers the version the product reports about itself.

The health endpoint reported a literal that no release step updated, so a cut
release served the previous version over its own health check. Removing the
literal fixes it once; these tests keep it fixed, by driving the real
``check-release-readiness.sh`` over copies of the tree in which the defect has
been deliberately reintroduced.

The script is copied rather than re-implemented: it resolves its repository root
from its own location, so a copy of the actual file is what runs here.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
READINESS = REPO_ROOT / "scripts" / "check-release-readiness.sh"

# Files the readiness check reads. Copied verbatim so a release version bump
# flows into these tests instead of stranding a fixture at an old version.
COPIED = (
    "scripts/check-release-readiness.sh",
    "package.json",
    "frontend-next/src/config/version.ts",
    "frontend-next/package.json",
    "frontend-next/package-lock.json",
    "agent/VERSION",
    "backend/setup.py",
    "backend/app/api/routes/agent_bootstrap.py",
    "backend/app/core/version.py",
    "backend/app/api/main.py",
    "backend/app/services/diagnostics_service.py",
    "backend/tests/api/test_agent_bootstrap_routes.py",
    "backend/tests/api/test_pra374_agent_artifact_redirects.py",
    "backend/tests/api/test_pra154_bootstrap_e2e.py",
)

# Files the readiness check only requires to exist.
PRESENT = (
    "CHANGELOG.md",
    "docs/maintainers/release-notes-template.md",
    "docs/upgrade-notes-1-0.md",
    "docs/maintainers/release-checklist.md",
    "docs/maintainers/agent-release.md",
    "docs/maintainers/ghcr-release-operations.md",
    "agent/packaging/README.md",
    "agent/packaging/install.sh",
    "agent/packaging/uninstall.sh",
    "agent/GO_VERSION",
    "agent/scripts/verify_sbom.py",
    "scripts/build_release_index.py",
    "scripts/check-release-absence.sh",
    "scripts/check-tag-commit.sh",
    "scripts/promote-release-images.sh",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/agent-release.yml",
)

BASH = shutil.which("bash")
GIT = shutil.which("git")

pytestmark = pytest.mark.skipif(
    BASH is None or GIT is None, reason="bash and git are required"
)


@pytest.fixture
def tree(tmp_path) -> Path:
    """A copy of the tree the readiness check inspects, otherwise release-ready."""
    root = tmp_path / "praxis"
    for rel in COPIED:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, dest)
    for rel in PRESENT:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.touch()
    # The check ends on `git diff --check`, which needs a repository to report
    # against. Nothing is committed, so an untracked copy is already clean.
    subprocess.run(
        [GIT, "-c", "init.defaultBranch=main", "init", "-q", str(root)],
        check=True,
        capture_output=True,
    )
    return root


def _run(tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, str(tree / "scripts" / "check-release-readiness.sh")],
        capture_output=True,
        text=True,
        timeout=120,
        # Failure is the result under test in most of these, not an error.
        check=False,
    )


def _edit(tree: Path, rel: str, old: str, new: str, occurrences: int = 1) -> None:
    path = tree / rel
    text = path.read_text(encoding="utf-8")
    assert (
        text.count(old) == occurrences
    ), f"{rel} no longer contains {old!r} {occurrences} time(s)"
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_a_release_ready_tree_passes(tree):
    result = _run(tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Reported version derivation" in result.stdout
    assert "backend/app/api/main.py states no release version literal" in result.stdout


def test_a_restated_version_in_the_health_surface_fails(tree):
    """The exact defect: a release version written into the application again."""
    _edit(
        tree,
        "backend/app/api/main.py",
        "version=get_version(),",
        'version="1.0.0",',
    )
    result = _run(tree)
    assert result.returncode != 0
    assert "backend/app/api/main.py restates a release version" in result.stdout
    assert "derive the version from backend/app/core/version.py" in result.stdout


def test_a_restated_version_in_the_support_bundle_fails(tree):
    _edit(
        tree,
        "backend/app/services/diagnostics_service.py",
        '"praxis_version": get_version(),',
        '"praxis_version": "1.0.0",',
        occurrences=2,
    )
    result = _run(tree)
    assert result.returncode != 0
    assert (
        "backend/app/services/diagnostics_service.py restates a release version"
        in result.stdout
    )


def test_a_release_literal_in_the_version_source_itself_fails(tree):
    """The fallback for an uninstalled tree must never be a release number."""
    _edit(
        tree,
        "backend/app/core/version.py",
        'UNKNOWN_VERSION = "0.0.0+unknown"',
        'UNKNOWN_VERSION = "1.0.0"',
    )
    result = _run(tree)
    assert result.returncode != 0
    assert "backend/app/core/version.py restates a release version" in result.stdout


def test_dropping_the_derivation_fails(tree):
    _edit(
        tree,
        "backend/app/api/main.py",
        "version=get_version(),",
        "version=PRODUCT_VERSION,",
    )
    result = _run(tree)
    assert result.returncode != 0
    assert (
        "backend/app/api/main.py does not call get_version() from "
        "backend/app/core/version.py" in result.stdout
    )


def test_a_missing_version_source_fails(tree):
    (tree / "backend" / "app" / "core" / "version.py").unlink()
    result = _run(tree)
    assert result.returncode != 0
    assert "no authoritative version source" in result.stdout
