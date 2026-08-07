"""Praxis-wide upstream trust anchors (PRA-158 #4a).

Manages the ``mirror_upstream_keys`` table: list, create-from-armored,
delete. Public material lives in DB; no Vault interaction. The
fingerprint is derived from the armored body via ``mirror_gpg`` so
operators don't have to compute it themselves (and can't get it
wrong, mismatching the body and the claimed fingerprint).

Slice #4b consumes ``build_keyring_for_verify`` to construct a
transient gpg keyring before the pre-sync verification gate.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import MirrorUpstreamKey
from . import mirror_gpg

logger = logging.getLogger(__name__)


class MirrorUpstreamKeyError(RuntimeError):
    """Raised on validation / GPG failures during upstream-key ops.

    Distinct from ``IntegrityError`` (DB constraint) so callers can
    distinguish "you already imported this key" from "the armored body
    is malformed."
    """


class MirrorUpstreamKeyService:
    """Manage Praxis-wide trust anchors used by the pre-sync verify
    gate (PRA-158 #4a/#4b).
    """

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Read paths
    # ------------------------------------------------------------------

    def list_keys(self) -> List[MirrorUpstreamKey]:
        return self.db.query(MirrorUpstreamKey).order_by(MirrorUpstreamKey.name).all()

    def get_by_id(self, key_id: int) -> Optional[MirrorUpstreamKey]:
        return (
            self.db.query(MirrorUpstreamKey)
            .filter(MirrorUpstreamKey.id == key_id)
            .one_or_none()
        )

    def get_by_fingerprint(self, fingerprint: str) -> Optional[MirrorUpstreamKey]:
        normalized = fingerprint.upper().strip()
        return (
            self.db.query(MirrorUpstreamKey)
            .filter(MirrorUpstreamKey.gpg_fingerprint == normalized)
            .one_or_none()
        )

    # ------------------------------------------------------------------
    # Write paths
    # ------------------------------------------------------------------

    def create_from_armored(
        self, *, name: str, armored_public_key: str, notes: Optional[str] = None
    ) -> MirrorUpstreamKey:
        """Import an armored public key, derive its fingerprint, persist.

        Raises:
            * ``MirrorUpstreamKeyError`` — armored body malformed,
              empty, contains multiple keys, or gpg rejects the import.
            * ``IntegrityError`` (re-raised) — fingerprint already in
              the table. Caller maps this to a 409 in the route layer.

        The DB column is the source of truth; the armored body is
        stored exactly as provided so re-exports are byte-identical to
        what the operator imported.
        """
        if not name or not name.strip():
            raise MirrorUpstreamKeyError("name is required")
        if not armored_public_key or not armored_public_key.strip():
            raise MirrorUpstreamKeyError("armored_public_key is required")

        # Derive the fingerprint via an ephemeral GNUPGHOME so the
        # caller doesn't have to provide it (and can't get it wrong).
        with mirror_gpg.ephemeral_gnupg_home() as home:
            try:
                fingerprint = mirror_gpg.import_public_and_extract_fingerprint(
                    home, armored_public_key
                )
            except mirror_gpg.MirrorGPGError as exc:
                raise MirrorUpstreamKeyError(
                    f"failed to import armored body: {exc}"
                ) from exc

        row = MirrorUpstreamKey(
            name=name.strip(),
            gpg_fingerprint=fingerprint,
            armored_public_key=armored_public_key,
            notes=notes,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise
        self.db.refresh(row)
        logger.info(
            "imported upstream trust anchor name=%r fingerprint=%s",
            name.strip(),
            fingerprint,
        )
        return row

    def delete(self, key_id: int) -> bool:
        row = self.get_by_id(key_id)
        if row is None:
            return False
        fingerprint = row.gpg_fingerprint
        self.db.delete(row)
        self.db.commit()
        logger.info(
            "deleted upstream trust anchor id=%d fingerprint=%s",
            key_id,
            fingerprint,
        )
        return True
