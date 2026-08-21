"""PRA-401: the production backend image pins one exact Python patch release.

``backend/Dockerfile.prod`` is a two stage build. The builder stage compiles
and installs dependencies into ``/opt/venv``; the runtime stage copies that
virtualenv over a fresh base image. Compiled extension modules in the venv are
built against one interpreter ABI and one C library, so the two stages have to
agree on the base image or the released container imports a venv it cannot use.

These tests guard the pin itself rather than a build:

- both stages exist and name the same base image tag;
- the tag is a fully qualified ``X.Y.Z-slim-bookworm`` reference, so a rebuild
  cannot silently drift onto a different patch release; and
- the pinned interpreter is at or above the supported runtime floor, so a
  revert to a superseded patch release fails here instead of shipping.

Raising the floor is a deliberate act: bump ``MINIMUM_PYTHON`` in the same
change that raises the Dockerfile pin.
"""

import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
DOCKERFILE = BACKEND / "Dockerfile.prod"

# Stages that must run the interpreter the release ships.
REQUIRED_STAGES = ("builder", "runtime")

# Debian codename the release image is built on. Changing it changes the glibc
# and OpenSSL the copied venv links against.
EXPECTED_VARIANT = "slim-bookworm"

# Lowest Python patch release supported by the production image.
MINIMUM_PYTHON = (3, 14, 7)

FROM_PATTERN = re.compile(
    r"^FROM\s+(?P<image>\S+)\s+AS\s+(?P<stage>\S+)\s*$",
    re.IGNORECASE,
)
PYTHON_TAG_PATTERN = re.compile(
    r"^python:(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)-(?P<variant>[a-z0-9.-]+)$"
)

if not DOCKERFILE.exists():  # pragma: no cover - layout guard
    pytest.skip("backend/Dockerfile.prod not available", allow_module_level=True)


def _stage_images() -> dict[str, str]:
    """Map stage name to base image for each named ``FROM ... AS`` stage.

    Comment lines are skipped so a base image mentioned in prose cannot stand in
    for a real instruction.
    """
    stages: dict[str, str] = {}
    for raw in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = FROM_PATTERN.match(line)
        if match:
            stages[match.group("stage").lower()] = match.group("image")
    return stages


def _python_stage_images() -> dict[str, str]:
    return {
        stage: image
        for stage, image in _stage_images().items()
        if image.startswith("python:")
    }


def test_the_expected_python_stages_are_present():
    stages = _stage_images()
    for name in REQUIRED_STAGES:
        assert name in stages, f"prod image must define a '{name}' stage"
        assert stages[name].startswith(
            "python:"
        ), f"the '{name}' stage must build on an official python base image"


def test_every_python_stage_pins_an_exact_patch_release():
    images = _python_stage_images()
    assert images, "prod image must build on an official python base image"
    for stage, image in images.items():
        match = PYTHON_TAG_PATTERN.match(image)
        assert match, (
            f"stage '{stage}' uses '{image}'; the prod image must pin a fully "
            "qualified python:X.Y.Z-<variant> tag, not a floating tag"
        )
        assert match.group("variant") == EXPECTED_VARIANT, (
            f"stage '{stage}' uses variant '{match.group('variant')}'; the prod "
            f"image is built on '{EXPECTED_VARIANT}'"
        )


def test_builder_and_runtime_share_one_base_image():
    stages = _python_stage_images()
    missing = [name for name in REQUIRED_STAGES if name not in stages]
    assert not missing, f"missing python stages: {missing}"
    distinct = {stages[name] for name in REQUIRED_STAGES}
    assert len(distinct) == 1, (
        "builder and runtime must pin the same python base image so the copied "
        f"/opt/venv matches the runtime interpreter; found {sorted(distinct)}"
    )


def test_the_pinned_interpreter_is_at_or_above_the_supported_floor():
    images = _python_stage_images()
    assert images, "prod image must build on an official python base image"
    floor = ".".join(str(part) for part in MINIMUM_PYTHON)
    for stage, image in images.items():
        match = PYTHON_TAG_PATTERN.match(image)
        assert match, f"stage '{stage}' does not pin a parseable python tag"
        version = (
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
        )
        assert version >= MINIMUM_PYTHON, (
            f"stage '{stage}' pins Python {'.'.join(str(p) for p in version)}; "
            f"the production image requires {floor} or newer"
        )
