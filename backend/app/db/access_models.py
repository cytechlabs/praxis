"""Fleet access models (PRA-137).

Core entities for M11 Zero-Trust Access Broker:

* ``FleetRole`` — role definition (built-in + user-defined). Governs what
  actions are allowed, whether session approval / TOTP is required, OS groups,
  sudoers, and login mode (per-user vs role-account).
* ``AccessBinding`` — grants a subject (user OR app-level role) access to a
  scope (static group OR smart group) with a given fleet role. XOR constraints
  on subject + scope enforced at the service layer.
* ``AccessGrant`` — materialised resolution of bindings × group membership.
  One row per (user, system, login) eligible combination. Powers the
  "Connect as..." dropdown and drives reconciliation.
* ``HostUserState`` — ledger of what Praxis believes is provisioned on each
  host. Reconciler converges host state to match DB grants.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .base import Base


class FleetRole(Base):  # pylint: disable=too-few-public-methods
    """Fleet role — permission bundle applied on a per-fleet basis."""

    __tablename__ = "fleet_roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    # "per_user" = cert principal == Praxis username -> account `alice`
    # "role_account" = cert principal == Praxis username -> shared local account `developer`
    login_mode = Column(String(20), nullable=False, server_default="per_user")
    # Only meaningful when login_mode == "role_account"
    role_account_name = Column(String(100), nullable=True)
    # JSON array: ["session_open", "command_exec", "file_transfer"]
    allowed_actions_json = Column(Text, nullable=False)
    session_requires_approval = Column(Boolean, nullable=False, server_default="false")
    totp_required = Column(Boolean, nullable=False, server_default="false")
    idle_timeout_s = Column(Integer, nullable=False, server_default="900")
    max_session_s = Column(Integer, nullable=False, server_default="3600")
    # PRA-141: per-fleet recording retention window (days).
    recording_retention_days = Column(Integer, nullable=False, server_default="90")
    # JSON array of OS groups to add the user to: ["docker", "wheel"]
    os_groups_json = Column(Text, nullable=False, server_default="[]")
    sudoers_snippet = Column(Text, nullable=True)
    # Built-in roles ship with the app; users can't delete them.
    is_builtin = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    bindings = relationship("AccessBinding", back_populates="fleet_role")


class AccessBinding(Base):  # pylint: disable=too-few-public-methods
    """Binds a subject (user OR app-level role) to a scope (group OR smart group).

    Exactly one of ``subject_user_id`` / ``subject_app_role_id`` must be set.
    Exactly one of ``scope_group_id`` / ``scope_smart_group_id`` must be set.
    Enforced at the service/schema layer.
    """

    __tablename__ = "access_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subject_user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    subject_app_role_id = Column(
        Integer,
        ForeignKey("role.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    scope_group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    scope_smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    fleet_role_id = Column(
        Integer,
        ForeignKey("fleet_roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    enabled = Column(Boolean, nullable=False, server_default="true")
    # JIT access grants set expires_at; reconciler auto-removes past expiry.
    expires_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    subject_user = relationship("User", foreign_keys=[subject_user_id], viewonly=True)
    subject_app_role = relationship(
        "Role", foreign_keys=[subject_app_role_id], viewonly=True
    )
    scope_group = relationship("Group", foreign_keys=[scope_group_id])
    scope_smart_group = relationship("SmartGroup", foreign_keys=[scope_smart_group_id])
    fleet_role = relationship("FleetRole", back_populates="bindings")


class AccessGrant(Base):  # pylint: disable=too-few-public-methods
    """Materialised (user, system, login) grant.

    Rebuilt by the reconciler when bindings or group memberships change.
    Serves as both the source for "Connect as..." resolution and the desired
    state the reconciler converges host accounts toward.
    """

    __tablename__ = "access_grants"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fleet_role_id = Column(
        Integer,
        ForeignKey("fleet_roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Per-user mode: login == Praxis user's username.
    # Role-account mode: login == fleet_role.role_account_name.
    login = Column(String(100), nullable=False)
    via_binding_id = Column(
        Integer,
        ForeignKey("access_bindings.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Marker row for the implicit "app admin -> everywhere" rule.
    is_implicit_admin = Column(Boolean, nullable=False, server_default="false")
    # PRA-284: effective expiry copied from the source AccessBinding at recompute.
    # NULL = never expires (implicit app-admin grants, whose boundary is app role +
    # active user, per PRA-290). Authorization treats ``expires_at <= now`` as
    # expired synchronously, so an expired grant stops authorizing at the decision
    # boundary without waiting for a recompute or cleanup sweep. Indexed for the
    # active-grant predicate.
    expires_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship("User")
    system = relationship("System")
    fleet_role = relationship("FleetRole")
    binding = relationship("AccessBinding")

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "system_id",
            "fleet_role_id",
            "login",
            name="uq_access_grant_user_system_role_login",
        ),
    )


class TotpChallenge(Base):  # pylint: disable=too-few-public-methods
    """Short-lived 'fresh TOTP' marker (PRA-139).

    A successful TOTP step-up inserts a row valid for ~15 minutes. The
    authorization service consults this when a fleet role sets
    ``totp_required=True`` and rejects the action if no live challenge
    exists for the user.
    """

    __tablename__ = "totp_challenges"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship("User")


class AccessRequest(Base):  # pylint: disable=too-few-public-methods
    """User-initiated JIT access request (PRA-139).

    On approval by an admin, the service creates a time-bound AccessBinding
    and links it here as ``resulting_binding_id``. Uses the same admin role
    that approves command_approvals — the multi-level vote spine from M10
    can be layered on later if needed.
    """

    __tablename__ = "access_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    requested_by = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fleet_role_id = Column(
        Integer,
        ForeignKey("fleet_roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=True,
    )
    scope_smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
        nullable=True,
    )
    justification = Column(Text, nullable=True)
    duration_seconds = Column(Integer, nullable=False, server_default="3600")
    # pending / approved / rejected / expired / revoked
    status = Column(String(20), nullable=False, server_default="pending", index=True)
    decided_by = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    decided_at = Column(DateTime, nullable=True)
    decision_comment = Column(Text, nullable=True)
    resulting_binding_id = Column(
        Integer,
        ForeignKey("access_bindings.id", ondelete="SET NULL"),
        nullable=True,
    )
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    requester = relationship("User", foreign_keys=[requested_by])
    decider = relationship("User", foreign_keys=[decided_by])
    fleet_role = relationship("FleetRole")
    scope_group = relationship("Group", foreign_keys=[scope_group_id])
    scope_smart_group = relationship("SmartGroup", foreign_keys=[scope_smart_group_id])
    resulting_binding = relationship(
        "AccessBinding", foreign_keys=[resulting_binding_id]
    )


class Session(Base):  # pylint: disable=too-few-public-methods
    """Interactive SSH session ledger (PRA-140).

    One row per opened terminal session. The runtime (paramiko channel,
    websocket glue) lives in-process; this is the persistent audit record
    and the anchor PRA-141 recordings point at.
    """

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fleet_role_id = Column(
        Integer,
        ForeignKey("fleet_roles.id", ondelete="SET NULL"),
        nullable=True,
    )
    login = Column(String(100), nullable=False)
    cert_serial = Column(String(255), nullable=True)
    client_ip = Column(String(64), nullable=True)
    # PRA-287: the CONSERVATIVE recording retention resolved across every allowing
    # role for this login at open time (longest retention wins), so a looser role
    # sharing the login cannot shorten the persisted recording window via the
    # representative ``fleet_role_id``. NULL on rows created before PRA-287 — recording
    # falls back to the representative role's value for those.
    recording_retention_days = Column(Integer, nullable=True)
    # opening / active / closed / idle_kill / max_duration / errored
    status = Column(String(20), nullable=False, server_default="opening", index=True)
    close_reason = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    max_expires_at = Column(DateTime, nullable=False)
    # PRA-153: which transport handled this session (ssh | agent).
    # NULL on rows created before PRA-153 shipped.
    transport = Column(String(8), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship("User")
    system = relationship("System")
    fleet_role = relationship("FleetRole")


class Recording(Base):  # pylint: disable=too-few-public-methods
    """Session recording metadata (PRA-141).

    File on disk is asciinema v2 (newline-delimited JSON). ``session_id`` is
    a unique back-reference to the Session row; ``retention_expires_at`` is
    stamped at ``start_recording`` using the fleet role's retention window.
    """

    __tablename__ = "recordings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(
        Integer,
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True,
    )
    file_path = Column(Text, nullable=False)
    size_bytes = Column(BigInteger, nullable=False, server_default="0")
    frame_count = Column(Integer, nullable=False, server_default="0")
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)
    retention_expires_at = Column(DateTime, nullable=False, index=True)
    # active | finalized | pruned | errored
    status = Column(String(20), nullable=False, server_default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    session = relationship("Session")
    user = relationship("User")
    system = relationship("System")


class FileTransferAudit(Base):  # pylint: disable=too-few-public-methods
    """One row per SFTP operation through the Praxis web UI (PRA-142)."""

    __tablename__ = "file_transfer_audits"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    login = Column(String(100), nullable=False)
    # upload | download | mkdir | unlink
    direction = Column(String(20), nullable=False)
    remote_path = Column(Text, nullable=False)
    local_filename = Column(Text, nullable=True)
    size_bytes = Column(BigInteger, nullable=False, server_default="0")
    sha256 = Column(String(64), nullable=True)
    # in_progress | success | error
    status = Column(
        String(20), nullable=False, server_default="in_progress", index=True
    )
    error_message = Column(Text, nullable=True)
    client_ip = Column(String(64), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)
    # PRA-153: which transport handled this transfer (ssh | agent).
    # NULL on rows created before PRA-153 shipped.
    transport = Column(String(8), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship("User")
    system = relationship("System")


class AuditEvent(Base):  # pylint: disable=too-few-public-methods
    """Stable-schema audit event (PRA-143).

    Every security-relevant action emits a row. ``context_json`` is the
    per-action payload documented in docs/audit-schema.md. Schema version
    bumps only on breaking changes so downstream SIEMs can rely on shape
    consistency.
    """

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    schema_version = Column(Integer, nullable=False, server_default="1")
    event_uuid = Column(String(36), nullable=False, unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    outcome = Column(String(20), nullable=False, server_default="success", index=True)
    actor_user_id = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_username = Column(String(200), nullable=True)
    actor_ip = Column(String(64), nullable=True)
    target_system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_kind = Column(String(40), nullable=True)
    target_id = Column(String(200), nullable=True)
    context_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    actor = relationship("User")
    target_system = relationship("System")


class AuditEventSystem(Base):  # pylint: disable=too-few-public-methods
    """Hosts affected by an audit event that has no single subject host.

    ``AuditEvent.target_system_id`` carries the one host an event is about, and
    stays empty for events that concern a set of hosts: a patch plan or
    execution spanning several targets, or a fleet-wide compliance evaluation.
    Collapsing such an event onto one host would assert something untrue, so the
    affected hosts are recorded here instead and a per-host query reads both
    places.

    Rows are written once beside the event and never updated. They index
    retrieval; they are not the evidence. The host identity captured at emission
    time lives in the event's own context, so losing a link row degrades a
    search and cannot rewrite history.
    """

    __tablename__ = "audit_event_systems"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(
        Integer,
        ForeignKey("audit_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("event_id", "system_id", name="uq_audit_event_system"),
    )

    event = relationship("AuditEvent")
    system = relationship("System")


class AuditSink(Base):  # pylint: disable=too-few-public-methods
    """Operator-configured external audit event sink (PRA-143)."""

    __tablename__ = "audit_sinks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    # syslog | http | file
    kind = Column(String(20), nullable=False)
    target = Column(String(1024), nullable=False)
    hmac_secret = Column(String(256), nullable=True)
    config_json = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AuditSinkDelivery(Base):  # pylint: disable=too-few-public-methods
    """Per-sink per-event delivery attempt ledger (PRA-143)."""

    __tablename__ = "audit_sink_deliveries"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    sink_id = Column(
        Integer,
        ForeignKey("audit_sinks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id = Column(
        Integer,
        ForeignKey("audit_events.id", ondelete="CASCADE"),
        nullable=False,
    )
    # pending | delivered | failed | dead_letter
    status = Column(String(20), nullable=False, server_default="pending", index=True)
    attempts = Column(Integer, nullable=False, server_default="0")
    last_error = Column(Text, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    sink = relationship("AuditSink")
    event = relationship("AuditEvent")


class HostUserState(Base):  # pylint: disable=too-few-public-methods
    """Ledger of Praxis-managed local accounts on each host.

    One row per (system, login). Reconciler writes this when it provisions
    or removes an account.
    """

    __tablename__ = "host_user_states"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    login = Column(String(100), nullable=False)
    # "per_user" | "role_account"
    mode = Column(String(20), nullable=False)
    # "pending" | "provisioned" | "pending_removal" | "removed" | "error"
    state = Column(String(20), nullable=False, server_default="pending")
    last_error = Column(Text, nullable=True)
    last_reconciled_at = Column(DateTime, nullable=True)
    home_archive_path = Column(Text, nullable=True)
    # PRA-282: set when the applied host state may still carry a fleet-role
    # sudoers drop-in that the 1.0 privilege baseline removed from the DB. Stays
    # True until a successful reconcile removes the drop-in on the host; a failed
    # reconcile leaves it True (and state="error") so the host is visibly pending
    # cleanup. A bounded interim marker for the PRA-285 reconcile scheduler.
    privilege_reconcile_pending = Column(
        Boolean, nullable=False, server_default="false"
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    system = relationship("System")

    __table_args__ = (
        UniqueConstraint("system_id", "login", name="uq_host_user_state_system_login"),
    )


class SessionLock(Base):  # pylint: disable=too-few-public-methods
    """Emergency cut-off (PRA-146).

    While an active row matches a subject (user XOR app role), every
    gated access action is denied for that subject and any live sessions
    are killed. The XOR is enforced both at the DB level (CheckConstraint)
    and in the service layer for clearer error messages.
    """

    __tablename__ = "session_locks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subject_user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    subject_app_role_id = Column(
        Integer,
        ForeignKey("role.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    reason = Column(Text, nullable=False)
    created_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    released_at = Column(DateTime, nullable=True, index=True)
    released_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "(subject_user_id IS NOT NULL) <> (subject_app_role_id IS NOT NULL)",
            name="ck_session_locks_subject_xor",
        ),
    )


class SessionApproval(Base):  # pylint: disable=too-few-public-methods
    """Single-use, time-windowed approval for a session open (PRA-147).

    Created in ``pending`` state by ``open_session`` when the matching
    fleet role has ``session_requires_approval=True``. Operators move it
    to ``granted`` (with a 5-min ``expires_at``) or ``denied``. The
    requester re-attempts ``open_session``, which atomically flips
    ``granted`` -> ``consumed`` and proceeds with the SSH connect. A
    grant left unused past ``expires_at`` is swept to ``expired``.
    """

    __tablename__ = "session_approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    requester_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    fleet_role_id = Column(
        Integer,
        ForeignKey("fleet_roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    login = Column(String(100), nullable=False)
    reason = Column(Text, nullable=True)
    state = Column(String(20), nullable=False, server_default="pending", index=True)
    approver_id = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    decision_reason = Column(Text, nullable=True)
    decided_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AccessReview(Base):  # pylint: disable=too-few-public-methods
    """Periodic access review (PRA-149).

    Captures a who-has-what-access sweep at a point in time. Items hold
    one frozen-snapshot row per ``AccessBinding`` in scope; the reviewer
    flips each to ``attest``, ``revoke``, or ``extend``.
    """

    __tablename__ = "access_reviews"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    # all | binding | user | role
    scope = Column(String(20), nullable=False)
    # Meaning depends on scope; null for ``all``.
    scope_ref_id = Column(Integer, nullable=True)
    # pending | completed | expired
    state = Column(String(20), nullable=False, server_default="pending", index=True)
    due_at = Column(DateTime, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    reviewer_id = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    summary = Column(Text, nullable=True)
    created_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    items = relationship(
        "AccessReviewItem",
        back_populates="review",
        cascade="all, delete-orphan",
    )


class AccessReviewItem(Base):  # pylint: disable=too-few-public-methods
    """Reviewer decision on a single binding within a review (PRA-149)."""

    __tablename__ = "access_review_items"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    review_id = Column(
        Integer,
        ForeignKey("access_reviews.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    binding_id = Column(
        Integer,
        # SET NULL so the audit row survives binding deletion.
        ForeignKey("access_bindings.id", ondelete="SET NULL"),
        nullable=True,
    )
    binding_snapshot_json = Column(Text, nullable=False)
    # pending | attest | revoke | extend
    action = Column(String(20), nullable=False, server_default="pending", index=True)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    review = relationship("AccessReview", back_populates="items")
    binding = relationship("AccessBinding", foreign_keys=[binding_id])


class RevocationWork(Base):  # pylint: disable=too-few-public-methods
    """PRA-285: persisted access-revocation / host-reconcile work (outbox).

    Enqueued in the SAME transaction as the grant recompute that narrowed access
    (outbox semantics: if narrowed grants commit, matching work exists), so a
    process restart never drops pending host cleanup. A row is a SIGNAL that a
    ``(user, system, login)`` scope needs reconvergence — NOT a stored "remove"
    imperative. The drain re-derives current desired state via
    ``fleet_reconciliation_service.reconcile_system`` at execution time, so access
    restored before the drain runs is preserved.

    ``system_id`` NULL means a user-scoped session sweep (e.g. emergency lock):
    close the user's remaining live sessions, no host reconcile. Idempotency is
    enforced at the service layer (one outstanding row per user/system/login).
    """

    __tablename__ = "revocation_work"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    # e.g. grant_recompute | binding_delete | binding_update | jit_revoke |
    # jit_expiry | role_removal | user_deactivation | access_review_revoke |
    # session_lock — carried for audit/reporting, not decision logic.
    reason = Column(String(48), nullable=False)
    source = Column(String(128), nullable=True)
    user_id = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    login = Column(String(100), nullable=True)
    # pending | error | completed
    status = Column(String(16), nullable=False, server_default="pending", index=True)
    attempt_count = Column(Integer, nullable=False, server_default="0")
    next_retry_at = Column(DateTime, nullable=True, index=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
    completed_at = Column(DateTime, nullable=True)
