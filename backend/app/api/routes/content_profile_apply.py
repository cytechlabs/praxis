"""``POST /systems/{id}/content-profile/apply`` (PRA-159 slice #3).

Mounts under ``/systems`` like the other host-scoped content-profile
routes from slice #1/#2. Awaits the orchestrator inline and returns
the structured ``ApplyContentProfileResponse``.

HTTP status mapping (locked):
  * 200 — ``state ∈ {applied, noop}``.
  * 409 — ``state ∈ {refused_no_profile, refused_conflict}``;
    operator must fix the binding before apply will run.
  * 502 — ``state == failed``; the host transport / credential issue
    / file write failed. Body still carries the structured
    ``ApplyContentProfileResponse`` so the operator UI can show
    ``written_paths`` / ``removed_paths`` for partial-state
    inspection. 502 (rather than 500) signals "downstream did the
    failing" — Praxis itself didn't crash, the host did.

Audit emit happens inside the orchestrator on the same DB session
as any credential mutations (PRA-158 ``safe_emit``-on-fresh-session
rule applies to single state transitions; apply is a multi-step op
where same-session emit is the right boundary). The route emits
nothing of its own.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.schemas.content_apply import ApplyContentProfileResponse
from app.core.auth import require_role
from app.db.models import System
from app.db.session import get_db
from app.services.access_authorization_service import scoped_system_ids
from app.services.broker_client import BrokerClient
from app.services.content_profile_apply import apply_content_profile_to_host
from app.services.ssh_service import SSHService
from app.services.transport.factory import get_transport

logger = logging.getLogger(__name__)

# Mounted at /systems by main.py so the URL lands at
# /systems/{system_id}/content-profile/apply.
router = APIRouter(tags=["content-profiles"])


@router.post(
    "/{system_id}/content-profile/apply",
    response_model=ApplyContentProfileResponse,
)
async def apply_content_profile(
    system_id: int,
    response: Response,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Apply the host's effective content profile.

    Locked steps (see ``content_profile_apply.apply_content_profile_to_host``):
      1. Resolve the host's effective profile + mirror entries.
      2. Refuse if the resolution isn't ``resolved`` (no_profile /
         conflict → 409).
      3. Ensure the trust bundle is installed for every distinct
         mirror in the resolved entries (PRA-158 install primitive).
      4. (Re-)issue per-(host, mirror) bearer credentials. Apply
         rotates credentials on every run — belt-and-braces against
         credential exposure on the host.
      5. Render praxis-profile-* files via the slice #3 source
         writer.
      6. Diff against existing managed files; write new + changed,
         remove obsolete.

    Returns the structured outcome with per-step counts. 502 on
    ``state=failed`` so operator dashboards distinguish "Praxis
    refused" (409) from "host transport failed" (502).
    """
    # PRA-281: apply drives real host mutation (transport setup, broker/SSH,
    # credential issuance, trust-bundle install, source-file writes/removes, audit).
    # A direct out-of-scope (or empty-scope) or nonexistent system id is a
    # non-disclosing 404 BEFORE the System lookup and every one of those steps.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and system_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )

    host = db.query(System).filter(System.id == system_id).one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )

    actor_user_id = getattr(current_user, "id", None)

    ssh_service = SSHService(db)
    async with BrokerClient() as broker:
        try:
            transport = await get_transport(host, broker, ssh_service=ssh_service)
        except Exception as exc:  # pylint: disable=broad-except
            # Transport setup failed before any host action — surface
            # as 502 with state=failed so the response shape stays
            # consistent with the orchestrator's own failure path.
            response.status_code = status.HTTP_502_BAD_GATEWAY
            return _failed_response(error=f"transport setup: {exc}")

        outcome = await apply_content_profile_to_host(
            db,
            host,
            transport,
            actor_user_id=actor_user_id,
        )

    if outcome.state in ("applied", "noop"):
        # Default 200; FastAPI uses the route's implicit 200 unless
        # the handler overrides via ``response.status_code``.
        return _outcome_to_response(outcome)
    if outcome.state.startswith("refused_"):
        response.status_code = status.HTTP_409_CONFLICT
        return _outcome_to_response(outcome)
    # outcome.state == "failed"
    response.status_code = status.HTTP_502_BAD_GATEWAY
    return _outcome_to_response(outcome)


def _outcome_to_response(outcome) -> dict:
    return {
        "state": outcome.state,
        "profile_slug": outcome.profile_slug,
        "written_paths": outcome.written_paths,
        "removed_paths": outcome.removed_paths,
        "trust_installed_for_mirrors": outcome.trust_installed_for_mirrors,
        "credentials_issued_for_mirrors": outcome.credentials_issued_for_mirrors,
        "error_text": outcome.error_text,
    }


def _failed_response(*, error: str) -> dict:
    return {
        "state": "failed",
        "profile_slug": None,
        "written_paths": [],
        "removed_paths": [],
        "trust_installed_for_mirrors": [],
        "credentials_issued_for_mirrors": [],
        "error_text": error,
    }
