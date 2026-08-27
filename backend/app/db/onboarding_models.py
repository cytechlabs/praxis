"""Guided first-system onboarding draft state.

A draft is the short-lived, operator-scoped workspace behind the guided Add
System flow. It exists so the wizard can connect, authenticate, verify and
discover a host *before* anything permanent is created: no ``System``,
``SystemMetadata``, ``SSHHostKey`` or facts row exists until the operator
finishes. A draft that fails, expires, or is abandoned therefore leaves no
managed host behind and consumes no license capacity.

Why a table and not process state
---------------------------------
The backend runs several workers alongside the scheduler, and consecutive
wizard steps are not guaranteed to land on the same one. Draft state has to be
durable and shared, so it lives in Postgres with two explicit concurrency
controls:

* ``state_version`` is optimistic concurrency for ordinary step writes. A write
  applies only when the caller's version still matches, so two browser tabs
  cannot silently interleave into a mixed draft.
* ``status`` plus ``finalizing_since`` is the finalization claim. Exactly one
  worker may move a draft out of ``active``; every other concurrent attempt
  loses the claim and is told so.

Secret custody
--------------
No column here can hold secret material. Passwords, private keys, passphrases,
sudo passwords, Vault tokens and Vault paths have no representation: the draft
records ``credential_id`` and nothing else about how that credential
authenticates. Inline credential creation goes to the credential API, which
writes to the secrets service, and only the resulting id comes back here.

``host_key_public`` is a *public* host key offered by the target during
verification. Holding it is what lets later steps pin the exact key the
operator approved, and it is promoted into the authoritative host-key store
only when the host becomes real.

``finalize_token_hash`` holds a digest, never the token. The plaintext is
returned once when the confirmation step is prepared and is not recoverable
from the database.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .base import Base

# Lifecycle states. ``finalizing`` is held only for the duration of one claimed
# finalization attempt; the sweeper releases a lease that outlives its bound.
DRAFT_STATUS_ACTIVE = "active"
DRAFT_STATUS_FINALIZING = "finalizing"
DRAFT_STATUS_COMPLETED = "completed"
DRAFT_STATUS_CANCELED = "canceled"
DRAFT_STATUS_EXPIRED = "expired"

DRAFT_STATUSES = (
    DRAFT_STATUS_ACTIVE,
    DRAFT_STATUS_FINALIZING,
    DRAFT_STATUS_COMPLETED,
    DRAFT_STATUS_CANCELED,
    DRAFT_STATUS_EXPIRED,
)

# Wizard steps, in order. ``current_step`` is a resume hint, not an authority:
# every step re-checks its own preconditions server-side.
STEP_CONNECT = "connect"
STEP_AUTHENTICATE = "authenticate"
STEP_VERIFY = "verify"
STEP_DISCOVER = "discover"
STEP_ORGANIZE = "organize"
STEP_CONFIRM = "confirm"
STEP_FINISH = "finish"

DRAFT_STEPS = (
    STEP_CONNECT,
    STEP_AUTHENTICATE,
    STEP_VERIFY,
    STEP_DISCOVER,
    STEP_ORGANIZE,
    STEP_CONFIRM,
    STEP_FINISH,
)

# Operator decision on the host key the target offered.
HOST_KEY_PENDING = "pending"
HOST_KEY_TRUSTED = "trusted"
HOST_KEY_REJECTED = "rejected"

HOST_KEY_DECISIONS = (HOST_KEY_PENDING, HOST_KEY_TRUSTED, HOST_KEY_REJECTED)

# Whether the actor held tenant-wide fleet scope when the draft was opened.
SCOPE_TENANT_WIDE = "tenant_wide"
SCOPE_SCOPED = "scoped"

SCOPE_KINDS = (SCOPE_TENANT_WIDE, SCOPE_SCOPED)


def _in_values(column: str, values: tuple) -> str:
    """Render a CHECK expression restricting ``column`` to ``values``."""
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


class SystemOnboardingDraft(Base):  # pylint: disable=too-few-public-methods
    """One in-progress guided onboarding session, private to its creator.

    Rows are written through ``app/services/onboarding_draft_service.py``,
    which owns the version/claim protocol and the typed serializers for the
    JSONB columns. Nothing else should write this table directly.
    """

    __tablename__ = "system_onboarding_drafts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # The only identifier that leaves the backend. The surrogate primary key is
    # never exposed, so drafts cannot be enumerated by counting.
    public_id = Column(String(43), nullable=False)

    # Actor binding. A draft is resumable only by the operator who created it:
    # it carries verification and host-key state, and letting a second actor
    # adopt it would launder the first actor's decisions.
    actor_user_id = Column(
        Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    # Digest of the actor's canonical sorted role set plus scope kind. Compared
    # on every privileged step and again at finalization; a changed authority
    # invalidates the draft rather than finalizing under authority the operator
    # no longer holds.
    actor_authority_digest = Column(String(64), nullable=False)
    actor_scope_kind = Column(String(16), nullable=False)

    status = Column(
        String(16), nullable=False, server_default=sa_text(f"'{DRAFT_STATUS_ACTIVE}'")
    )
    current_step = Column(
        String(16), nullable=False, server_default=sa_text(f"'{STEP_CONNECT}'")
    )

    # Optimistic concurrency for step writes.
    state_version = Column(Integer, nullable=False, server_default=sa_text("0"))

    # Anti-replay capability for finalization. Digest only.
    finalize_token_hash = Column(String(64), nullable=True)

    # Sliding TTL, and the hard ceiling a slide can never pass.
    expires_at = Column(DateTime, nullable=False)
    absolute_expires_at = Column(DateTime, nullable=False)

    # Set while a finalization claim is held, so a crashed worker's lease can be
    # released instead of wedging the draft forever.
    finalizing_since = Column(DateTime, nullable=True)

    # Typed, bounded, allow-listed payloads. Shapes live in
    # ``app/api/schemas/onboarding.py``; nothing writes a raw dict here.
    connection = Column(JSONB, nullable=False, server_default=sa_text("'{}'::jsonb"))
    organization = Column(JSONB, nullable=False, server_default=sa_text("'{}'::jsonb"))
    verification = Column(JSONB, nullable=True)
    discovery = Column(JSONB, nullable=True)

    # The exact public host key the target offered, pinned for the rest of the
    # draft and promoted through the authoritative host-key helper at finish.
    host_key_type = Column(String(50), nullable=True)
    host_key_public = Column(Text, nullable=True)
    host_key_fingerprint = Column(String(255), nullable=True)
    host_key_decision = Column(
        String(16), nullable=False, server_default=sa_text(f"'{HOST_KEY_PENDING}'")
    )

    # Set when the operator explicitly declines verification. The resulting host
    # is honest about it rather than being reported Active.
    verification_skipped = Column(
        Boolean, nullable=False, server_default=sa_text("false")
    )

    # References only. Every one is revalidated at finalization, and every one
    # nulls out rather than blocking deletion of the object it points at.
    credential_id = Column(
        Integer, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True
    )
    ssh_security_policy_id = Column(
        Integer,
        ForeignKey("ssh_security_policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    group_id = Column(
        Integer, ForeignKey("groups.id", ondelete="SET NULL"), nullable=True
    )
    distro_id = Column(
        Integer, ForeignKey("distros.id", ondelete="SET NULL"), nullable=True
    )

    # Replay anchor: once set, a repeated finish returns this system instead of
    # creating a second host or consuming a second license seat.
    finalized_system_id = Column(
        Integer, ForeignKey("systems.id", ondelete="SET NULL"), nullable=True
    )

    completed_at = Column(DateTime, nullable=True)
    canceled_at = Column(DateTime, nullable=True)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )

    actor = relationship("User")
    credential = relationship("Credential")
    ssh_security_policy = relationship("SSHSecurityPolicy")
    group = relationship("Group")
    distro = relationship("Distro")
    finalized_system = relationship("System")

    __table_args__ = (
        UniqueConstraint("public_id", name="system_onboarding_drafts_public_id_uniq"),
        CheckConstraint(
            _in_values("status", DRAFT_STATUSES),
            name="system_onboarding_drafts_status_check",
        ),
        CheckConstraint(
            _in_values("current_step", DRAFT_STEPS),
            name="system_onboarding_drafts_step_check",
        ),
        CheckConstraint(
            _in_values("host_key_decision", HOST_KEY_DECISIONS),
            name="system_onboarding_drafts_host_key_decision_check",
        ),
        CheckConstraint(
            _in_values("actor_scope_kind", SCOPE_KINDS),
            name="system_onboarding_drafts_scope_kind_check",
        ),
        Index(
            "ix_system_onboarding_drafts_actor_status",
            "actor_user_id",
            "status",
        ),
        Index("ix_system_onboarding_drafts_expires_at", "expires_at"),
    )
