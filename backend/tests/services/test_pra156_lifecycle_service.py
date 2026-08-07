"""PRA-156 #3a: LifecycleService.compute unit tests.

Locked verdict matrix:

  * Stale OR missing facts (freshness != "fresh") → unknown,
    unknown_reason="freshness".
  * Missing distro_id_facts or distro_release → unknown,
    unknown_reason="missing_distro_facts".
  * No matching standard-support row in distro_lifecycle → unknown,
    unknown_reason="no_lifecycle_row".
  * today > eol_date → unsupported, days_to_eol negative.
  * today == eol_date → approaching-eol, days_to_eol == 0
    (boundary lock — #3e fires host_eol_reached on this day).
  * today < eol_date AND days_to_eol <= APPROACHING_EOL_WINDOW_DAYS
    → approaching-eol.
  * Else → supported.
  * #3a only consumes support_kind="standard" rows; ESM rows are
    invisible until #3e wires the override path.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.db.models import DistroLifecycle
from app.services import lifecycle_service
from app.services.lifecycle_service import (
    APPROACHING_EOL_WINDOW_DAYS,
    LIFECYCLE_APPROACHING_EOL,
    LIFECYCLE_SUPPORTED,
    LIFECYCLE_UNKNOWN,
    LIFECYCLE_UNSUPPORTED,
    UNKNOWN_REASON_FRESHNESS,
    UNKNOWN_REASON_MISSING_DISTRO_FACTS,
    UNKNOWN_REASON_NO_LIFECYCLE_ROW,
)

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def today() -> date:
    """Reference date for the verdict matrix.

    Fixed because every assertion is relative to it. Lifecycle math
    is deterministic given (today, eol_date), so the calendar-bomb
    rule (PRA-155 pre-review self-check) does NOT apply here — the
    test is intentionally driving boundary states. Real production
    callers pass ``datetime.utcnow().date()``.
    """
    return date(2026, 5, 2)


@pytest.fixture
def lifecycle_rows(db):
    """Seed the boundary cases plus a standard+esm pair.

    The praxis_test DB may already carry the production seed from a
    prior Alembic run; wipe the table first so this fixture owns the
    state for its run. The outer-transaction rollback in conftest
    restores everything at teardown.
    """
    db.query(DistroLifecycle).delete()
    db.flush()
    rows = [
        # Past-EOL: standard ended a year ago.
        DistroLifecycle(
            distro_id="ubuntu",
            release="20.04",
            eol_date=date(2025, 4, 29),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Day-zero boundary: EOL exactly on `today`.
        DistroLifecycle(
            distro_id="ubuntu",
            release="boundary-zero",
            eol_date=date(2026, 5, 2),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Inside the approaching window (39 days out).
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=date(2026, 6, 10),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Just inside the approaching window: EOL exactly
        # APPROACHING_EOL_WINDOW_DAYS out.
        DistroLifecycle(
            distro_id="ubuntu",
            release="boundary-window",
            eol_date=date(2026, 5, 2) + timedelta(days=APPROACHING_EOL_WINDOW_DAYS),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Just outside the window: one day past the threshold.
        DistroLifecycle(
            distro_id="ubuntu",
            release="boundary-window-plus-one",
            eol_date=date(2026, 5, 2) + timedelta(days=APPROACHING_EOL_WINDOW_DAYS + 1),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Comfortably supported.
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2027, 6, 1),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # ESM row paired with the supported release. #3a must NOT
        # consult this row; #3e wires it in via overrides.
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2032, 6, 1),
            support_kind="esm",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # ESM-only release: standard row absent. Without an override
        # in place, #3a should treat this as no_lifecycle_row.
        DistroLifecycle(
            distro_id="ubuntu",
            release="esm-only",
            eol_date=date(2030, 1, 1),
            support_kind="esm",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
    ]
    for row in rows:
        db.add(row)
    db.flush()
    db.commit()
    return rows


# ---------------------------------------------------------------- unknown


def test_stale_facts_return_unknown(db, today, lifecycle_rows):
    """Stale freshness short-circuits the lookup — even a real
    matching row returns unknown."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="stale",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_FRESHNESS
    assert verdict.days_to_eol is None
    assert verdict.eol_date is None


def test_missing_facts_return_unknown(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="missing",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_FRESHNESS


def test_missing_distro_id_returns_unknown(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts=None,
        distro_release="22.04",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_MISSING_DISTRO_FACTS


def test_empty_distro_release_returns_unknown(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_MISSING_DISTRO_FACTS


def test_unknown_distro_combination_returns_unknown(db, today, lifecycle_rows):
    """Distro+release pair with no row in the lifecycle table."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="freebsd",
        distro_release="14",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_NO_LIFECYCLE_ROW


# ---------------------------------------------------------------- boundary


def test_unsupported_when_today_past_eol(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="20.04",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_UNSUPPORTED
    assert verdict.days_to_eol < 0
    assert verdict.eol_date == date(2025, 4, 29)
    assert verdict.support_kind == "standard"


def test_day_zero_is_approaching_eol_with_zero_days(db, today, lifecycle_rows):
    """Boundary lock: today == eol_date is approaching-eol with
    days_to_eol=0, NOT unsupported. #3e fires host_eol_reached on
    this transition."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="boundary-zero",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_APPROACHING_EOL
    assert verdict.days_to_eol == 0


def test_inside_window_is_approaching(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="debian",
        distro_release="12",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_APPROACHING_EOL
    assert verdict.days_to_eol == (date(2026, 6, 10) - today).days


def test_window_boundary_inclusive(db, today, lifecycle_rows):
    """EOL exactly APPROACHING_EOL_WINDOW_DAYS out is approaching-eol."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="boundary-window",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_APPROACHING_EOL
    assert verdict.days_to_eol == APPROACHING_EOL_WINDOW_DAYS


def test_window_boundary_exclusive(db, today, lifecycle_rows):
    """One day past the window is supported."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="boundary-window-plus-one",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.days_to_eol == APPROACHING_EOL_WINDOW_DAYS + 1


def test_supported_when_well_outside_window(db, today, lifecycle_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2027, 6, 1)
    assert verdict.support_kind == "standard"


# ---------------------------------------------------------------- esm scoping


def test_esm_row_does_not_extend_standard_in_3a(db, today, lifecycle_rows):
    """Ubuntu 22.04 has both a standard row (2027-06-01) and an ESM
    row (2032-06-01). #3a must use the standard row only — the
    override path that picks the ESM date lands in #3e."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
    )
    assert verdict.eol_date == date(2027, 6, 1)
    assert verdict.support_kind == "standard"


def test_esm_only_release_is_unknown_in_3a(db, today, lifecycle_rows):
    """A release with an ESM row but no standard row returns
    no_lifecycle_row — #3a doesn't promote ESM into the default
    lookup. Operators get override-driven behavior in #3e."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="esm-only",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_UNKNOWN
    assert verdict.unknown_reason == UNKNOWN_REASON_NO_LIFECYCLE_ROW


# ---------------------------------------------------------------- rhel-family normalization


@pytest.fixture
def rhel_family_rows(db):
    """Seed major-only rows for the three RHEL-family distros.

    Mirrors the production seed (which carries 7/8/9 majors only) so
    we can prove the lookup normalizes minor releases like ``8.10``
    and ``9.4`` to the major row. Wipes the table first so this
    fixture owns the state for its run; the conftest's outer-
    transaction rollback restores everything at teardown.
    """
    db.query(DistroLifecycle).delete()
    db.flush()
    rows = [
        DistroLifecycle(
            distro_id="rhel",
            release="8",
            eol_date=date(2029, 5, 31),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        DistroLifecycle(
            distro_id="rhel",
            release="9",
            eol_date=date(2032, 5, 31),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        DistroLifecycle(
            distro_id="rocky",
            release="9",
            eol_date=date(2032, 5, 31),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        DistroLifecycle(
            distro_id="almalinux",
            release="9",
            eol_date=date(2032, 5, 31),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
        # Ubuntu LTS designator: "22.04" is NOT major.minor — a fallback
        # to "22" must NOT happen for ubuntu. Seed the real row so the
        # exact match works, and assert below that the absence of a
        # "22" row is irrelevant.
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2027, 6, 1),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        ),
    ]
    for row in rows:
        db.add(row)
    db.flush()
    db.commit()
    return rows


def test_rhel_minor_release_falls_back_to_major(db, today, rhel_family_rows):
    """RHEL 8.10 has no exact row, but ``"8"`` does — normalization
    finds the major row and returns its verdict."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rhel",
        distro_release="8.10",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2029, 5, 31)


def test_rocky_minor_release_falls_back_to_major(db, today, rhel_family_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rocky",
        distro_release="9.4",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2032, 5, 31)


def test_almalinux_minor_release_falls_back_to_major(db, today, rhel_family_rows):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="almalinux",
        distro_release="9.5",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2032, 5, 31)


def test_exact_minor_row_wins_over_major_fallback(db, today, rhel_family_rows):
    """If an operator seeds ``(rhel, 8.10, standard)`` to record a
    per-minor support quirk, that row takes precedence over the
    ``(rhel, 8, standard)`` major row — exact match always wins."""
    db.add(
        DistroLifecycle(
            distro_id="rhel",
            release="8.10",
            eol_date=date(2030, 1, 1),
            support_kind="standard",
            source="vendor-bulletin",
            as_of=date(2026, 5, 2),
        )
    )
    db.flush()
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rhel",
        distro_release="8.10",
        today=today,
        freshness="fresh",
    )
    assert verdict.eol_date == date(2030, 1, 1)
    assert verdict.source == "vendor-bulletin"


def test_ubuntu_does_not_fall_back_to_major(db, today, rhel_family_rows):
    """Ubuntu's ``22.04`` is an LTS designator, not major.minor.
    The normalization must NOT strip ``22.04`` to ``22`` — a missing
    LTS row must be honestly unknown rather than silently mapped to
    a non-existent major row."""
    # Sanity: exact "22.04" works.
    exact = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
    )
    assert exact.status == LIFECYCLE_SUPPORTED

    # An ubuntu release with no seeded row must not be rescued by
    # stripping to a "20" major.
    missing = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="20.04",
        today=today,
        freshness="fresh",
    )
    assert missing.status == LIFECYCLE_UNKNOWN
    assert missing.unknown_reason == UNKNOWN_REASON_NO_LIFECYCLE_ROW


def test_rhel_major_only_release_still_works(db, today, rhel_family_rows):
    """Regression guard: a host that already reports just ``"9"``
    (uncommon but possible on some images) still hits the major row
    via the exact-match path on the first candidate."""
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rhel",
        distro_release="9",
        today=today,
        freshness="fresh",
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2032, 5, 31)


def test_smart_group_ids_param_accepted_and_ignored_in_3a(db, today, lifecycle_rows):
    """The signature carries smart_group_ids forward to #3e without
    a future API break, but #3a must produce the same verdict
    regardless of what's passed."""
    base = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
    )
    with_groups = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=[1, 2, 3],
    )
    assert base == with_groups
