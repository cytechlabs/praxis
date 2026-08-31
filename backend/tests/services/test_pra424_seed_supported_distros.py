"""PRA-424: every supported release in the published matrix is seeded at start.

Onboarding maps a discovered host onto a ``distros`` row. A release the support
matrix claims as Supported but startup seeding never creates reads to an
operator as an unsupported distribution, which is the wrong answer and blocks
the guided flow on a currently shipping host.

These tests read the Supported tier out of ``docs/support-matrix.md`` and the
standard end-of-life dates out of the lifecycle snapshot the matrix cites, and
hold the startup seed to both. Adding a row to the matrix without seeding it
fails here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.db.models import Distro
from scripts.seed_data import DISTRO_DEFINITIONS, seed_data

_REPO_ROOT = Path(__file__).resolve().parents[3]
SUPPORT_MATRIX = _REPO_ROOT / "docs" / "support-matrix.md"
LIFECYCLE_SNAPSHOT = (
    _REPO_ROOT / "backend" / "app" / "db" / "seed_data" / "distro_lifecycle.json"
)

# The matrix names distributions the way an operator says them; the catalogue
# and the lifecycle snapshot each carry their own spelling of the same thing.
MATRIX_TO_CATALOGUE = {
    "Ubuntu LTS": "Ubuntu",
    "Debian": "Debian",
    "RHEL": "RHEL",
    "Rocky Linux": "Rocky Linux",
    "AlmaLinux": "AlmaLinux",
}
CATALOGUE_TO_LIFECYCLE = {
    "Ubuntu": "ubuntu",
    "Debian": "debian",
    "RHEL": "rhel",
    "Rocky Linux": "rocky",
    "AlmaLinux": "almalinux",
}


def _supported_rows():
    """(catalogue name, release) for every row in the matrix's Supported tier."""
    text = SUPPORT_MATRIX.read_text(encoding="utf-8")
    section = text.split("### Supported", 1)[1].split("### Best-effort", 1)[0]

    rows = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 2 or cells[0] == "Distro":
            continue
        name = MATRIX_TO_CATALOGUE.get(cells[0])
        assert name is not None, f"unmapped matrix distro {cells[0]!r}"
        for release in cells[1].split(","):
            release = release.strip()
            if re.fullmatch(r"[0-9]+(\.[0-9]+)?", release):
                rows.append((name, release))
    assert rows, "the Supported tier of the support matrix parsed as empty"
    return rows


def _standard_eol():
    """``(lifecycle id, release) -> standard end-of-life date`` from the snapshot."""
    snapshot = json.loads(LIFECYCLE_SNAPSHOT.read_text(encoding="utf-8"))
    return {
        (entry["distro_id"], entry["release"]): entry["eol_date"]
        for entry in snapshot["entries"]
        if entry["support_kind"] == "standard"
    }


def test_every_supported_release_has_a_startup_seed():
    seeded = {(name, version) for name, version, _release, _eol in DISTRO_DEFINITIONS}
    missing = [row for row in _supported_rows() if row not in seeded]
    assert not missing, f"supported releases with no startup seed: {missing}"


def test_seeded_supported_releases_carry_the_documented_end_of_life_date():
    eol_by_release = _standard_eol()
    seeded = {
        (name, version): eol for name, version, _release, eol in DISTRO_DEFINITIONS
    }

    mismatched = []
    for name, version in _supported_rows():
        documented = eol_by_release.get((CATALOGUE_TO_LIFECYCLE[name], version))
        assert documented is not None, (
            f"{name} {version} is Supported but has no standard end-of-life "
            "entry in the lifecycle snapshot"
        )
        if seeded[(name, version)].isoformat() != documented:
            mismatched.append((name, version, seeded[(name, version)], documented))
    assert not mismatched, f"seeded dates disagree with the matrix: {mismatched}"


def test_the_seed_definitions_name_each_release_once():
    keys = [(name, version) for name, version, _release, _eol in DISTRO_DEFINITIONS]
    assert len(keys) == len(set(keys))


class _KeepOpenSession:
    """Hands the seeder the per-test session while neutering ``close()``.

    ``seed_data`` closes the session it opens; the fixture owns that lifecycle
    and needs the connection alive to roll the test back afterwards.
    """

    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    @staticmethod
    def close():
        return None


def test_seeding_creates_every_supported_release_and_repeats_cleanly(db, monkeypatch):
    import scripts.seed_data as seed_module

    monkeypatch.setattr(seed_module, "SessionLocal", lambda: _KeepOpenSession(db))

    seed_data()
    seed_data()

    for name, version in _supported_rows():
        matches = db.query(Distro).filter_by(name=name, version=version).all()
        assert len(matches) == 1, f"{name} {version} was not seeded exactly once"
