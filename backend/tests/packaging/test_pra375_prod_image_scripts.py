"""PRA-375: the production image must not ship privileged diagnostic spikes.

``backend/Dockerfile.prod`` copies ``backend/scripts/`` into ``/app/scripts``
wholesale, so anything dropped under that directory reaches the released image.
The obsolete ``scripts/spikes/`` diagnostics read the backend Vault token and
could mint a real agent certificate when invoked inside a running container.

These tests are a packaging regression guard:

- ``backend/scripts/spikes/`` is gone from the source tree;
- no maintained backend source or documentation still points at the deleted
  scripts (the commit-pinned unused-import audit inventory is historical and is
  excluded by design);
- the production Dockerfile keeps a build-time assertion, ordered after the
  runtime script copy, that fails the build if ``/app/scripts/spikes`` ever
  reappears; and
- the maintained runtime scripts the image depends on are still copied and
  still wired to the entrypoint.
"""

from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
REPO = Path(__file__).resolve().parents[3]
DOCKERFILE = BACKEND / "Dockerfile.prod"
SCRIPTS_DIR = BACKEND / "scripts"

DELETED_SCRIPTS = ("spike_peer_cert_uvicorn.py", "verify_cold_stack.py")

# The runtime script copy target and the directory that must never survive it.
SCRIPTS_COPY = "COPY --from=builder /build/scripts /app/scripts"
FORBIDDEN_IMAGE_PATH = "/app/scripts/spikes"

# Scripts the running production container actually needs.
REQUIRED_SCRIPTS = ("start.prod.sh", "load_dotenv.py")

SCANNED_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".prod",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIPPED_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules"}

if not DOCKERFILE.exists():  # pragma: no cover - layout guard
    pytest.skip("backend/Dockerfile.prod not available", allow_module_level=True)


def _instructions(text: str) -> list[str]:
    """Dockerfile logical instructions: comments dropped, continuations joined.

    Keeps a comment mentioning the forbidden path from satisfying an assertion
    that a real instruction is supposed to satisfy.
    """
    joined: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1].strip() + " "
            continue
        joined.append((buffer + line).strip())
        buffer = ""
    if buffer:
        joined.append(buffer.strip())
    return joined


def _scanned_files() -> list[Path]:
    roots = [BACKEND, REPO / "docs"]
    excluded_tree = REPO / "docs" / "audits" / "py-w2000"
    out: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIPPED_DIRS for part in path.parts):
                continue
            if excluded_tree in path.parents:
                continue
            if path == Path(__file__):
                continue
            if path.suffix not in SCANNED_SUFFIXES and not path.name.startswith(
                "Dockerfile"
            ):
                continue
            out.append(path)
    return out


# --------------------------------------------------- source tree


def test_spikes_directory_is_gone_from_the_source_tree():
    assert not (
        SCRIPTS_DIR / "spikes"
    ).exists(), "backend/scripts/spikes must not exist; it ships into the prod image"


def test_no_maintained_source_references_the_deleted_spike_scripts():
    offenders: list[str] = []
    for path in _scanned_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary/unreadable
            continue
        for name in DELETED_SCRIPTS:
            if name in text:
                offenders.append(f"{path.relative_to(REPO)} -> {name}")
    assert not offenders, "stale references to deleted spike scripts: " + ", ".join(
        offenders
    )


def test_required_runtime_scripts_still_exist():
    for name in REQUIRED_SCRIPTS:
        assert (SCRIPTS_DIR / name).is_file(), f"backend/scripts/{name} is required"


# --------------------------------------------------- image contract


def test_prod_image_copies_the_runtime_scripts_directory():
    assert SCRIPTS_COPY in _instructions(
        DOCKERFILE.read_text()
    ), "prod image must copy backend/scripts into /app/scripts"


def test_prod_image_fails_the_build_when_spikes_are_present():
    instructions = _instructions(DOCKERFILE.read_text())
    guards = [
        i
        for i in instructions
        if i.startswith("RUN ") and FORBIDDEN_IMAGE_PATH in i and "exit 1" in i
    ]
    assert guards, (
        f"prod image must assert {FORBIDDEN_IMAGE_PATH} is absent and fail the "
        "build (RUN ... exit 1) if it is not"
    )
    guard = guards[0]
    assert (
        f"-e {FORBIDDEN_IMAGE_PATH}" in guard
    ), "the guard must test for the path itself, not a single file inside it"


def test_spike_guard_runs_after_the_scripts_copy():
    instructions = _instructions(DOCKERFILE.read_text())
    copy_at = instructions.index(SCRIPTS_COPY)
    guard_positions = [
        i
        for i, text in enumerate(instructions)
        if text.startswith("RUN ") and FORBIDDEN_IMAGE_PATH in text and "exit 1" in text
    ]
    assert guard_positions, "no spikes guard instruction found in the prod image"
    assert (
        guard_positions[0] > copy_at
    ), "the spikes guard must run after /app/scripts is copied"


def test_prod_image_keeps_the_entrypoint_script_wired():
    instructions = _instructions(DOCKERFILE.read_text())
    assert any(
        i.startswith("RUN ") and "chmod +x /app/scripts/start.prod.sh" in i
        for i in instructions
    ), "prod image must make the entrypoint script executable"
    assert any(
        i.startswith("CMD ") and "/app/scripts/start.prod.sh" in i for i in instructions
    ), "prod image must launch /app/scripts/start.prod.sh"
