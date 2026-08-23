"""PRA-281 Slice 6: fleet-scope visibility for patch update executions.

A patch update execution fans out to many target hosts
(``PatchUpdateExecutionHost.system_id_snapshot``), so — unlike a single
``{system_id}`` route — visibility is a set relationship: an execution is
visible/operable to a scoped caller only when EVERY materialized target host is
inside the caller's fleet scope. This fails closed for out-of-scope-only AND
mixed-scope executions (a scoped caller must never see, operate on, or export a
run that touches a host they cannot access).

Admins reach tenant-wide scope through the shared spine (``scoped_system_ids``
returns ``None``); these helpers treat ``scope is None`` as "no restriction" and
defer existence checks to the calling route/service so exact not-found messages
are preserved.

Null-snapshot policy (documented decision): a materialized execution host with a
``NULL`` ``system_id_snapshot`` cannot be attributed to a system, so for a scoped
caller it does NOT count toward the in-scope target set. An execution whose only
target hosts are null/unresolvable therefore has an empty in-scope target set and
is treated as NOT visible (conservative — never expose a run we cannot prove is
entirely in scope). Admins are unaffected.
"""

from __future__ import annotations

from typing import Optional, Set

from sqlalchemy.orm import Session

from ..db.models import PatchUpdateExecutionHost, PatchUpdatePlanHost


def execution_target_system_ids(db: Session, execution_id: int) -> Set[int]:
    """The set of resolvable target system ids for an execution (non-null
    ``system_id_snapshot`` values across its materialized hosts)."""
    rows = (
        db.query(PatchUpdateExecutionHost.system_id_snapshot)
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .all()
    )
    return {r[0] for r in rows if r[0] is not None}


def execution_wave_target_system_ids(
    db: Session, execution_id: int, wave_index: int
) -> Set[int]:
    """The resolvable target system ids for one wave of an execution.

    Narrower than :func:`execution_target_system_ids`: a wave event concerns the
    hosts in that wave, so attributing it to the whole execution would put it in
    the history of hosts it never touched."""
    rows = (
        db.query(PatchUpdateExecutionHost.system_id_snapshot)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.wave_index == wave_index,
        )
        .all()
    )
    return {r[0] for r in rows if r[0] is not None}


def execution_visible_to_scope(
    db: Session, execution_id: int, scope: Optional[Set[int]]
) -> bool:
    """Whether an execution is visible/operable in the caller's fleet scope.

    ``scope is None`` (admin) → always visible (existence is enforced by the
    route/service). Otherwise the execution's resolvable target systems must be
    non-empty AND entirely within scope; a nonexistent execution resolves to an
    empty set and is therefore not visible (indistinguishable from out-of-scope —
    non-disclosing)."""
    if scope is None:
        return True
    ids = execution_target_system_ids(db, execution_id)
    return bool(ids) and ids.issubset(scope)


def plan_target_system_ids(db: Session, plan_id: int) -> Set[int]:
    """The set of resolvable target system ids for a plan (non-null
    ``PatchUpdatePlanHost.system_id`` values)."""
    rows = (
        db.query(PatchUpdatePlanHost.system_id)
        .filter(PatchUpdatePlanHost.plan_id == plan_id)
        .all()
    )
    return {r[0] for r in rows if r[0] is not None}


def plan_visible_to_scope(db: Session, plan_id: int, scope: Optional[Set[int]]) -> bool:
    """Whether a plan may be started/inspected in the caller's fleet scope.

    Same subset semantics as :func:`execution_visible_to_scope`: admin
    (``scope is None``) always; otherwise the plan's resolvable target systems
    must be non-empty and entirely in scope (fail closed for out-of-scope-only,
    mixed-scope, and empty/unresolvable plans)."""
    if scope is None:
        return True
    ids = plan_target_system_ids(db, plan_id)
    return bool(ids) and ids.issubset(scope)
