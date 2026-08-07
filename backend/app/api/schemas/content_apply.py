"""Pydantic schemas for the content-profile apply route (PRA-159 #3)."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel


class ApplyContentProfileResponse(BaseModel):
    """Response shape of ``POST /systems/{id}/content-profile/apply``.

    ``state`` mirrors ``ApplyOutcome.state`` from the orchestrator:

      * ``applied`` — files written / removed; HTTP 200.
      * ``noop`` — already in the desired state; HTTP 200.
      * ``refused_no_profile`` — host has no effective profile; HTTP 409.
      * ``refused_conflict`` — multiple profiles tied at the winning
        tier; HTTP 409.
      * ``failed`` — partial state possible; HTTP 502 (the host
        transport / credential issue / write failed). ``error_text``
        carries the operator-actionable signal.
    """

    state: Literal[
        "applied",
        "noop",
        "refused_no_profile",
        "refused_conflict",
        "failed",
    ]
    profile_slug: Optional[str]
    written_paths: List[str]
    removed_paths: List[str]
    trust_installed_for_mirrors: List[str]
    credentials_issued_for_mirrors: List[str]
    error_text: Optional[str]
