"""SSH CA rotation + user cert revocation (PRA-128).

Two operations:

- ``rotate_ca``: regenerate the Vault SSH CA keypair, bump ca_identifier, clear
  ``ca_trust_deployed`` on every system (admin redeploys explicitly), record a
  history row, drop in-memory SSH connection pool so outstanding sessions
  re-sign on next use.

- ``revoke_user_certs``: same outcome minus the Vault rotation — existing
  short-lived certs complete their TTL but Praxis immediately drops pooled
  connections so new operations force fresh signing, and ca_identifier
  bumps for audit.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ..db.models import CARotation, SSHIdentitySettings, System

logger = logging.getLogger(__name__)


def _generate_identifier() -> str:
    return f"ca-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


def _record_rotation(
    db: Session,
    event_type: str,
    ca_identifier: str,
    ca_public_key: Optional[str],
    performed_by: Optional[int],
) -> CARotation:
    row = CARotation(
        event_type=event_type,
        ca_identifier=ca_identifier,
        ca_public_key=ca_public_key,
        performed_by=performed_by,
        performed_at=datetime.utcnow(),
    )
    db.add(row)
    return row


def _clear_ca_trust_flags(db: Session) -> int:
    """Mark every system as needing CA trust redeploy."""
    updated = (
        db.query(System)
        .filter(System.ca_trust_deployed.is_(True))
        .update(
            {
                System.ca_trust_deployed: False,
                System.ca_trust_deployed_at: None,
            },
            synchronize_session=False,
        )
    )
    return updated


def _drop_ssh_pool():
    """Close every pooled SSH connection so new ops force fresh auth.

    SSHService manages a module-level singleton pool keyed by hostname. We
    instantiate a fresh service and ask it to close all — that runs against
    the shared pool dict on the class.
    """
    try:
        from ..db.session import SessionLocal
        from .ssh_service import SSHService

        tmp_db = SessionLocal()
        try:
            SSHService(tmp_db).close_all_connections()
        finally:
            tmp_db.close()
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Failed to drop SSH connection pool: %s", e)


def _get_or_create_settings(db: Session) -> SSHIdentitySettings:
    settings = db.query(SSHIdentitySettings).first()
    if not settings:
        settings = SSHIdentitySettings(user_cert_ttl_seconds=300)
        db.add(settings)
        db.flush()
    return settings


def rotate_ca(
    db: Session,
    performed_by: Optional[int],
    vault_service=None,
) -> Dict[str, Any]:
    """Regenerate Vault SSH CA; mark fleet for redeploy. Returns summary."""
    from .vault_service import VaultService

    vs = vault_service or VaultService(db)
    new_public_key = vs.rotate_ssh_ca()

    settings = _get_or_create_settings(db)
    settings.ca_identifier = _generate_identifier()

    flagged = _clear_ca_trust_flags(db)
    _record_rotation(db, "rotate", settings.ca_identifier, new_public_key, performed_by)
    db.commit()

    _drop_ssh_pool()

    return {
        "event_type": "rotate",
        "ca_identifier": settings.ca_identifier,
        "ca_public_key": new_public_key,
        "systems_flagged_for_redeploy": flagged,
    }


def revoke_user_certs(
    db: Session,
    performed_by: Optional[int],
) -> Dict[str, Any]:
    """Stop honouring existing short-lived user certs without re-rotating CA.

    v1 behaviour: bump ca_identifier for audit + drop pooled SSH connections
    so next operation forces a fresh cert sign. Existing pooled sessions are
    terminated immediately; any orphan connection outside the pool completes
    its 5-minute TTL.
    """
    settings = _get_or_create_settings(db)
    settings.ca_identifier = _generate_identifier()
    _record_rotation(db, "revoke", settings.ca_identifier, None, performed_by)
    db.commit()

    _drop_ssh_pool()

    return {
        "event_type": "revoke",
        "ca_identifier": settings.ca_identifier,
    }


def list_rotations(db: Session, limit: int = 50) -> list:
    rows = (
        db.query(CARotation).order_by(CARotation.performed_at.desc()).limit(limit).all()
    )
    return [
        {
            "id": r.id,
            "event_type": r.event_type,
            "ca_identifier": r.ca_identifier,
            "performed_by": r.performed_by,
            "performed_at": r.performed_at.isoformat() + "Z"
            if r.performed_at
            else None,
        }
        for r in rows
    ]
