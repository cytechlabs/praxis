"""PRA-390: persistent data mounts must be writable by the non-root runtime user.

Docker preserves the image's ownership of a mount point when it first
initializes a named volume. If the production image does not pre-create a mount
point, the volume lands ``root:root`` and the backend (UID/GID 1000) cannot
write there. For the recordings volume that took down session recording while
sessions kept opening, which is an audit bypass rather than a degraded feature.

These tests are a packaging regression guard:

- every ``/data/praxis/*`` path the Compose files mount into the backend is
  pre-created in ``backend/Dockerfile.prod``;
- the same tree is chowned to ``praxis:praxis``; and
- both happen before the image drops privileges with ``USER praxis``, since a
  ``mkdir``/``chown`` afterwards would run unprivileged and cannot fix ownership.

A runtime writability check runs against an already-built production image when
``PRAXIS_PROD_IMAGE`` names one and docker is available; it skips otherwise so
the suite never depends on building an image.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
REPO = Path(__file__).resolve().parents[3]
DOCKERFILE = BACKEND / "Dockerfile.prod"
COMPOSE_FILES = (REPO / "docker-compose.yml", REPO / "docker-compose.prod.yml")
UPGRADE_NOTES = REPO / "docs" / "upgrade-notes-1-0.md"

# Ledger/close reason a refused session records. Pinned to
# ``session_service.UNRECORDED_ABORT_REASON`` by the service tests; repeated here
# as a literal so this module stays import-free.
REFUSAL_REASON = "recording_unavailable"

RUNTIME_USER = "praxis"
RUNTIME_UID = "1000"
DROP_PRIVILEGES = f"USER {RUNTIME_USER}"

# The mount point the incident was about. Listed explicitly so the contract does
# not silently weaken if the Compose files are ever reorganized.
RECORDINGS_PATH = "/data/praxis/recordings"

# `- <volume>:/data/praxis/<dir>` mount entries. The `<volume>:` prefix keeps
# environment entries that merely mention a path from being read as mounts.
_MOUNT = re.compile(r"^-\s+[A-Za-z0-9_.-]+:(/data/praxis/[A-Za-z0-9_.-]+)(:ro)?$")

if not DOCKERFILE.exists():  # pragma: no cover - layout guard
    pytest.skip("backend/Dockerfile.prod not available", allow_module_level=True)


def _instructions(text: str) -> list[str]:
    """Dockerfile logical instructions: comments dropped, continuations joined.

    Keeps a comment mentioning a path from satisfying an assertion that a real
    instruction is supposed to satisfy.
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


def _mounted_data_paths() -> set[str]:
    """Every ``/data/praxis`` path the Compose files mount as a volume."""
    found: set[str] = set()
    for path in COMPOSE_FILES:
        if not path.exists():  # pragma: no cover - layout guard
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            match = _MOUNT.match(raw.strip())
            if match:
                found.add(match.group(1))
    return found


def _index_of_privilege_drop(instructions: list[str]) -> int:
    for i, text in enumerate(instructions):
        if text == DROP_PRIVILEGES:
            return i
    raise AssertionError("prod image must drop privileges with USER praxis")


# --------------------------------------------------- image contract


def test_compose_mounts_the_recordings_volume():
    """Guards the test itself: the mount discovery must actually find it."""
    assert RECORDINGS_PATH in _mounted_data_paths()


def test_every_mounted_data_path_is_precreated_in_the_prod_image():
    instructions = _instructions(DOCKERFILE.read_text(encoding="utf-8"))
    mkdirs = [i for i in instructions if i.startswith("RUN ") and "mkdir -p" in i]
    missing = [
        path
        for path in sorted(_mounted_data_paths())
        if not any(path in i for i in mkdirs)
    ]
    assert not missing, (
        "prod image must pre-create every mounted data path or the named volume "
        f"initializes root-owned: {', '.join(missing)}"
    )


def test_prod_image_owns_the_data_tree_as_the_runtime_user():
    instructions = _instructions(DOCKERFILE.read_text(encoding="utf-8"))
    chowns = [
        i
        for i in instructions
        if i.startswith("RUN ") and f"chown -R {RUNTIME_USER}:{RUNTIME_USER} /data" in i
    ]
    assert chowns, (
        f"prod image must chown the /data tree to {RUNTIME_USER}:{RUNTIME_USER} so "
        "the non-root backend can write every persistent mount"
    )


def test_mount_points_are_created_and_owned_before_privileges_drop():
    instructions = _instructions(DOCKERFILE.read_text(encoding="utf-8"))
    drop_at = _index_of_privilege_drop(instructions)
    setup = [
        i
        for i, text in enumerate(instructions)
        if text.startswith("RUN ")
        and RECORDINGS_PATH in text
        and "mkdir -p" in text
        and f"chown -R {RUNTIME_USER}:{RUNTIME_USER} /data" in text
    ]
    assert setup, (
        f"prod image must create and chown {RECORDINGS_PATH} in a single "
        "instruction so the mount point is never left root-owned"
    )
    assert setup[0] < drop_at, (
        "mount-point creation and chown must run before USER praxis; afterwards "
        "the build is unprivileged and cannot set ownership"
    )


def test_runtime_user_is_uid_1000():
    """Ownership only helps if the runtime user is the UID the volume gets."""
    instructions = _instructions(DOCKERFILE.read_text(encoding="utf-8"))
    assert any(
        i.startswith("RUN ") and f"--uid {RUNTIME_UID}" in i and RUNTIME_USER in i
        for i in instructions
    ), f"prod image must create {RUNTIME_USER} with UID {RUNTIME_UID}"
    assert any(
        i.startswith("RUN ") and f"--gid {RUNTIME_UID}" in i and RUNTIME_USER in i
        for i in instructions
    ), f"prod image must create the {RUNTIME_USER} group with GID {RUNTIME_UID}"


# --------------------------------------------------- operator remediation


def test_upgrade_notes_carry_the_existing_volume_repair():
    """The image fix only helps a volume Docker has yet to initialize.

    A `recordings_data` volume that already holds recordings keeps its root
    ownership across the upgrade, and every interactive session on that
    deployment is then refused. Operators need the in-place repair, so the
    upgrade notes must carry it and must stay pinned to the path, UID/GID, and
    ledger reason the code actually uses.
    """
    assert UPGRADE_NOTES.exists(), "operator upgrade notes are missing"
    notes = UPGRADE_NOTES.read_text(encoding="utf-8")

    assert REFUSAL_REASON in notes, "operators cannot match the symptom to the cause"
    assert RECORDINGS_PATH in notes, "the repair must name the container path"
    assert (
        f"chown -R {RUNTIME_UID}:{RUNTIME_UID} {RECORDINGS_PATH}" in notes
    ), "the repair command must chown the recordings path to the runtime UID/GID"
    assert (
        f"stat -c '%u:%g' {RECORDINGS_PATH}" in notes
    ), "a read-only ownership check must come before the repair"
    assert (
        "Do not delete and recreate the volume" in notes
    ), "recreating the volume destroys existing cast files, which are audit records"


def test_upgrade_notes_verify_the_repair_as_the_backend_user():
    """The verification must be a real write, run as the user that records."""
    notes = UPGRADE_NOTES.read_text(encoding="utf-8")
    assert f"touch {RECORDINGS_PATH}/.write-check" in notes
    assert (
        "--user root" not in notes.split("Confirm the repair")[-1]
    ), "the verification must not run as root, or it proves nothing"


# --------------------------------------------------- runtime check


@pytest.mark.skipif(
    not os.environ.get("PRAXIS_PROD_IMAGE") or shutil.which("docker") is None,
    reason="set PRAXIS_PROD_IMAGE to a built production image and provide docker",
)
def test_built_image_mount_point_is_writable_by_the_runtime_user():
    image = os.environ["PRAXIS_PROD_IMAGE"]
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image,
            "-c",
            f'id -u; stat -c "%u:%g" {RECORDINGS_PATH}; '
            f"touch {RECORDINGS_PATH}/.writable && echo WRITABLE",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    uid, ownership, writable = proc.stdout.split()
    assert uid == RUNTIME_UID
    assert ownership == f"{RUNTIME_UID}:{RUNTIME_UID}"
    assert writable == "WRITABLE"
