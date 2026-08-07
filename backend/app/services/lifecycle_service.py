"""PRA-156 slice #3a + #3e-a: LifecycleService.

Computes per-host distro lifecycle verdicts from the PRA-155 host facts
layer plus the ``distro_lifecycle`` reference table, with optional
override consultation against ``distro_lifecycle_override`` for
smart-group-scoped extended-support contracts. Transport-neutral —
SSH-only hosts and agent-enrolled hosts both produce the same verdict
shape, because they both populate ``host_facts.distro_id_facts`` and
``host_facts.distro_release`` through the same ``FactsService.ingest``
path.

Locked rules (from PRA-156 design lock):

  * Lifecycle is **derived, not stored** on ``host_facts``. No
    materialization layer; recompute on every read. Cheap — single
    indexed lookup.
  * Boundary semantics (LOCKED):
      ``today > eol_date``  → ``unsupported``
      ``today == eol_date`` → ``approaching-eol`` with ``days_to_eol=0``
                              (and #3e fires ``host_eol_reached``)
      ``0 < days_to_eol <= APPROACHING_EOL_WINDOW_DAYS`` → ``approaching-eol``
      else                  → ``supported``
  * Stale OR missing facts (PRA-155 freshness verdict ``"missing"`` /
    ``"stale"``) → ``unknown``. Unknown is the verdict, not a fallback —
    the saved-view filter for unknown hosts must match these.
  * No matching ``(distro_id, release)`` row → ``unknown``.
  * Override behavior (PRA-156 #3e-a, locked): if the system belongs
    to a smart group with a matching ``distro_lifecycle_override``
    row, the override's ``eol_date`` / ``support_kind`` / ``source``
    replace the standard row. Multiple matching overrides → latest
    ``eol_date`` wins, then newest ``updated_at``, then highest
    ``id`` (deterministic tie-break). Override lookup mirrors the
    standard row's RHEL-family normalization: exact release wins,
    then major fallback for rhel/rocky/almalinux.
  * Standard-row lookup still consumes only ``support_kind='standard'``
    rows from ``distro_lifecycle``. The override surface is separate:
    if an operator wants ESM/extended support to apply to a group,
    they record it in ``distro_lifecycle_override`` rather than
    promoting the seed's ESM rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from ..db.models import (
    DistroLifecycle,
    DistroLifecycleOverride,
    HostFacts,
    SmartGroupMembership,
    System,
)
from .facts_freshness import freshness_of

# Lifecycle status values. Hyphenated to match the predicate field
# names that #3c will accept (e.g. ``lifecycle.status == "approaching-eol"``).
LIFECYCLE_SUPPORTED = "supported"
LIFECYCLE_APPROACHING_EOL = "approaching-eol"
LIFECYCLE_UNSUPPORTED = "unsupported"
LIFECYCLE_UNKNOWN = "unknown"

LIFECYCLE_STATUSES = frozenset(
    (
        LIFECYCLE_SUPPORTED,
        LIFECYCLE_APPROACHING_EOL,
        LIFECYCLE_UNSUPPORTED,
        LIFECYCLE_UNKNOWN,
    )
)

# Days-out window that flips a host into ``approaching-eol``. Backend
# constant per the lock; app-settings configurability deferred until an
# operator asks. The fleet dashboard widget in #3d and the alert
# thresholds in #3e are independent of this — they each carry their own
# numeric inputs.
APPROACHING_EOL_WINDOW_DAYS = 90


# RHEL-family hosts report ``/etc/os-release`` ``VERSION_ID`` with the
# minor included — e.g. ``"8.10"``, ``"9.4"``, ``"9.5"`` — but EOL data
# is per-major. The PRA-155 collectors persist whatever the host
# reports verbatim (correct: rounding at collection time would lose
# information the smart-group / read paths might want), so the lookup
# does the normalization here. For these distros, an exact-release
# match wins; on miss, retry with the major-only release. Other
# families (Ubuntu LTS designators, Debian majors) already match the
# seed exactly and don't need this fallback.
_RHEL_FAMILY_DISTRO_IDS = frozenset({"rhel", "rocky", "almalinux"})


def _candidate_releases(distro_id: str, release: str) -> list[str]:
    """Lookup candidates for ``release``, in priority order.

    Exact match always comes first so an operator who explicitly
    seeded ``(rhel, 8.10, standard)`` to record a per-minor support
    quirk is honored. The major fallback only fires for RHEL-family
    distros AND only when the release contains a minor segment, so
    Ubuntu's ``"22.04"`` (LTS designator, not "22 minor 04") can't
    accidentally fall through to a non-existent ``"22"`` row.
    """
    candidates = [release]
    if distro_id in _RHEL_FAMILY_DISTRO_IDS and "." in release:
        major = release.split(".", 1)[0]
        if major and major != release:
            candidates.append(major)
    return candidates


@dataclass(frozen=True)
class LifecycleVerdict:
    """Result of a single ``compute`` call.

    ``status`` is one of ``LIFECYCLE_STATUSES``. The remaining fields
    are populated only when a verdict was reached — for ``unknown``
    they are ``None`` and ``unknown_reason`` carries the discriminator
    so the read API and audit row can record WHY a host is unknown
    without leaking it into the smart-group predicate (which only
    reads ``status``).
    """

    status: str
    days_to_eol: Optional[int]
    eol_date: Optional[date]
    support_kind: Optional[str]
    source: Optional[str]
    unknown_reason: Optional[str] = None


# Discriminators on the ``unknown`` verdict. UI / audit can surface
# these to explain WHY a host is unknown; the smart-group predicate in
# #3c does NOT branch on them.
UNKNOWN_REASON_FRESHNESS = "freshness"
UNKNOWN_REASON_MISSING_DISTRO_FACTS = "missing_distro_facts"
UNKNOWN_REASON_NO_LIFECYCLE_ROW = "no_lifecycle_row"


def _unknown(reason: str) -> LifecycleVerdict:
    return LifecycleVerdict(
        status=LIFECYCLE_UNKNOWN,
        days_to_eol=None,
        eol_date=None,
        support_kind=None,
        source=None,
        unknown_reason=reason,
    )


def compute(
    db: Session,
    *,
    distro_id_facts: Optional[str],
    distro_release: Optional[str],
    today: date,
    freshness: str,
    smart_group_ids: Optional[Iterable[int]] = None,
) -> LifecycleVerdict:
    """Return a lifecycle verdict for one host.

    Args:
        db: Active SQLAlchemy session.
        distro_id_facts: Host-reported distro id from
            ``host_facts.distro_id_facts`` (e.g. ``"ubuntu"``,
            ``"rhel"``). ``None``/empty → ``unknown``.
        distro_release: Host-reported release from
            ``host_facts.distro_release`` (e.g. ``"22.04"``, ``"9"``).
            ``None``/empty → ``unknown``.
        today: Reference date for the EOL math. Caller passes
            ``datetime.utcnow().date()`` in production; tests pass a
            fixed date to drive boundary assertions.
        freshness: PRA-155 freshness verdict for the underlying facts
            row — one of ``"missing"`` / ``"stale"`` / ``"fresh"``.
            Anything other than ``"fresh"`` → ``unknown``.
        smart_group_ids: System's smart-group memberships. PRA-156 #3e-a:
            when present, ``distro_lifecycle_override`` rows scoped to
            those groups are consulted FIRST; the latest matching
            override (by ``eol_date`` then ``updated_at`` then ``id``)
            replaces the standard-row verdict.
    """
    # Stale or missing facts: lifecycle is unknown regardless of what
    # the facts row says about the distro. This is the saved-view
    # filter source-of-truth for the ``unknown`` bucket.
    if freshness != "fresh":
        return _unknown(UNKNOWN_REASON_FRESHNESS)

    if not distro_id_facts or not distro_release:
        return _unknown(UNKNOWN_REASON_MISSING_DISTRO_FACTS)

    # PRA-156 #3e-a: override lookup. When the host belongs to any
    # smart group with a matching override row, the override's
    # ``eol_date`` / ``support_kind`` / ``source`` replace the
    # standard-row verdict. Override absence is non-fatal — fall
    # through to the standard row.
    chosen_eol_date = None
    chosen_support_kind = None
    chosen_source = None
    if smart_group_ids:
        override_row = _pick_override(
            db, distro_id_facts, distro_release, smart_group_ids
        )
        if override_row is not None:
            chosen_eol_date = override_row.eol_date
            chosen_support_kind = override_row.support_kind
            chosen_source = override_row.source

    # Standard-support row lookup. Skipped if an override already
    # produced the verdict — overrides REPLACE the standard row, they
    # don't extend it. Candidate list applies the RHEL-family
    # normalization (exact first, then major-only).
    if chosen_eol_date is None:
        row = None
        for candidate in _candidate_releases(distro_id_facts, distro_release):
            row = (
                db.query(DistroLifecycle)
                .filter(
                    DistroLifecycle.distro_id == distro_id_facts,
                    DistroLifecycle.release == candidate,
                    DistroLifecycle.support_kind == "standard",
                )
                .one_or_none()
            )
            if row is not None:
                break
        if row is None:
            return _unknown(UNKNOWN_REASON_NO_LIFECYCLE_ROW)
        chosen_eol_date = row.eol_date
        chosen_support_kind = row.support_kind
        chosen_source = row.source

    days_to_eol = (chosen_eol_date - today).days

    if days_to_eol < 0:
        status = LIFECYCLE_UNSUPPORTED
    elif days_to_eol == 0:
        # Boundary lock: day-zero is ``approaching-eol`` with
        # ``days_to_eol=0``, NOT ``unsupported``. #3e fires
        # ``host_eol_reached`` on this transition.
        status = LIFECYCLE_APPROACHING_EOL
    elif days_to_eol <= APPROACHING_EOL_WINDOW_DAYS:
        status = LIFECYCLE_APPROACHING_EOL
    else:
        status = LIFECYCLE_SUPPORTED

    return LifecycleVerdict(
        status=status,
        days_to_eol=days_to_eol,
        eol_date=chosen_eol_date,
        support_kind=chosen_support_kind,
        source=chosen_source,
    )


def _pick_override(
    db: Session,
    distro_id_facts: str,
    distro_release: str,
    smart_group_ids: Iterable[int],
) -> Optional[DistroLifecycleOverride]:
    """Pick the winning override row for a host.

    Mirrors the standard-row lookup discipline: exact release wins
    over RHEL-family major fallback. Among rows at the same precedence
    tier, latest ``eol_date`` wins, then newest ``updated_at``, then
    highest ``id`` as the deterministic tie-break (so two operators
    adding overrides on the same day with the same EOL date still get
    a stable verdict).

    Returns ``None`` if no scoped override matches.
    """
    group_ids = list(smart_group_ids)
    if not group_ids:
        return None
    for candidate in _candidate_releases(distro_id_facts, distro_release):
        winner = (
            db.query(DistroLifecycleOverride)
            .filter(
                DistroLifecycleOverride.scope_type == "smart_group",
                DistroLifecycleOverride.scope_id.in_(group_ids),
                DistroLifecycleOverride.distro_id == distro_id_facts,
                DistroLifecycleOverride.release == candidate,
            )
            .order_by(
                DistroLifecycleOverride.eol_date.desc(),
                DistroLifecycleOverride.updated_at.desc(),
                DistroLifecycleOverride.id.desc(),
            )
            .first()
        )
        if winner is not None:
            return winner
    return None


# ----------------------------------------------------------------- bulk index


def compute_for_all_systems(
    db: Session,
    *,
    today: Optional[date] = None,
    now: Optional[datetime] = None,
) -> Dict[int, LifecycleVerdict]:
    """Return ``{system_id: LifecycleVerdict}`` for every System.

    Used by the smart-group predicate compiler (PRA-156 #3c) so a
    membership recompute does ONE bulk fetch + N pure-Python
    computations instead of N indexed queries per group. At fleet
    scale (15-200 hosts per the PRA-131 cap) this collapses what
    would otherwise be ``hosts × lifecycle_groups`` round-trips into
    a single fetch shared across the whole rule evaluation.

    Hosts with no ``host_facts`` row land in the index with
    ``status="unknown"`` and ``unknown_reason="freshness"`` —
    matching the per-host ``compute()`` verdict for the same
    inputs. Every system gets an entry; lifecycle predicates can
    therefore evaluate against the index without null-handling
    games (the namespace lock for ``lifecycle.*``: unknown is a
    real value, not a null fall-through).

    Args:
        db: Active session.
        today: Reference date for the EOL math. Defaults to UTC
            today; tests pass a fixed date.
        now: Reference time for the freshness verdict. Defaults to
            UTC now; tests pass a fixed datetime to drive
            stale-boundary states.
    """
    today = today or datetime.utcnow().date()

    rows = (
        db.query(
            System.id,
            HostFacts.distro_id_facts,
            HostFacts.distro_release,
            HostFacts.collected_at,
        )
        .outerjoin(HostFacts, HostFacts.system_id == System.id)
        .all()
    )

    # PRA-156 #3e-a: bulk-load smart-group memberships once so
    # ``compute(...)``'s override lookup gets the right scope per
    # system without N per-system membership queries. Empty list for
    # systems with no memberships is fine — _pick_override short-
    # circuits on empty input.
    membership_index: Dict[int, List[int]] = {}
    for system_id, smart_group_id in db.query(
        SmartGroupMembership.system_id, SmartGroupMembership.smart_group_id
    ).all():
        membership_index.setdefault(system_id, []).append(smart_group_id)

    index: Dict[int, LifecycleVerdict] = {}
    for system_id, distro_id_facts, distro_release, collected_at in rows:
        freshness = freshness_of(collected_at, now=now)
        index[system_id] = compute(
            db,
            distro_id_facts=distro_id_facts,
            distro_release=distro_release,
            today=today,
            freshness=freshness,
            smart_group_ids=membership_index.get(system_id),
        )
    return index
