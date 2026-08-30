"""
Database models for the application.
Contains User, Role, and UserRole models to represent users and their roles.
Also contains models for Linux system management including Systems, Groups, Credentials,
Packages, PackageUpdates, and Distros.
"""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, Column, Date, DateTime
from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, Index, Integer, String, Table, Text, UniqueConstraint
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import relationship

# Import fleet access models (PRA-137, PRA-139, PRA-140, PRA-141)
from .access_models import (  # noqa: F401; pylint: disable=unused-import
    AccessBinding,
    AccessGrant,
    AccessRequest,
    AuditEvent,
    AuditEventSystem,
    AuditSink,
    AuditSinkDelivery,
    FileTransferAudit,
    FleetRole,
    HostUserState,
    Recording,
    Session,
    TotpChallenge,
)
from .base import Base

# Import command execution models to make them available for relationships
from .command_execution_models import (  # noqa: F401; pylint: disable=unused-import
    CommandExecutionMetrics,
    CommandExecutionPolicy,
    CommandExecutionQueue,
    CommandExecutionResult,
    CommandExecutionSystemPolicy,
    CommandExecutionUserPolicy,
    CommandResourceLimit,
)

# Import compliance policy models (PRA-165 slice 1 + slice 2,
# PRA-167 slice 1-4, PRA-176 slice 1).
from .compliance_models import (  # noqa: F401; pylint: disable=unused-import
    CompliancePolicy,
    CompliancePolicyCheck,
    CompliancePolicyEvidence,
    ComplianceRemediationExecutionAttempt,
    ComplianceRemediationPlan,
    ComplianceRemediationRequest,
)

# Import the guided onboarding draft model so Base.metadata picks it up for
# create_all() / alembic autogenerate.
from .onboarding_models import (  # noqa: F401; pylint: disable=unused-import
    SystemOnboardingDraft,
)

# Import report-run + schedule models (PRA-178 Slice 2 + Slice 5) so
# Base.metadata picks them up for create_all() / alembic autogenerate.
from .report_models import (  # noqa: F401; pylint: disable=unused-import
    ReportRun,
    ReportSchedule,
)

# Import the PRA-169 rolling-window scheduler claim state so
# Base.metadata.create_all() picks it up in the test fixture.
from .scheduler_models import (  # noqa: F401; pylint: disable=unused-import
    SchedulerJobLock,
)

# Import SSH security models to make them available for relationships
from .ssh_security_models import SSHHostKey  # pylint: disable=unused-import
from .ssh_security_models import SSHSecurityLog  # pylint: disable=unused-import
from .ssh_security_models import (  # noqa: F401; pylint: disable=unused-import
    SSHSecurityPolicy,
)

# Association table for user-role relationship
user_role = Table(
    "user_role",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("user.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("role.id"), primary_key=True),
    Column("created_at", DateTime, default=datetime.utcnow),
    Column("updated_at", DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
)

# Association table for system-tag relationship
system_tag = Table(
    "system_tag",
    Base.metadata,
    Column(
        "system_id",
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "tag_id",
        Integer,
        ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("created_at", DateTime, default=datetime.utcnow),
)


class Tag(Base):  # pylint: disable=too-few-public-methods
    """Tag model for labeling and categorizing systems."""

    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    color = Column(String(7), nullable=False, server_default="#6B7280")
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    systems = relationship("System", secondary=system_tag, back_populates="tags")
    creator = relationship("User")


class Role(Base):  # pylint: disable=too-few-public-methods
    """Role model for user permissions."""

    __tablename__ = "role"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users = relationship("User", secondary=user_role, back_populates="roles")


class User(Base):  # pylint: disable=too-few-public-methods
    """User model."""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    oidc_sub = Column(String, nullable=True)  # OIDC subject identifier
    oidc_issuer = Column(String, nullable=True)  # OIDC issuer URL (multi-IdP staging)
    # PRA-139: TOTP second-factor enrollment
    totp_secret = Column(String(64), nullable=True)
    totp_enrolled_at = Column(DateTime, nullable=True)
    totp_recovery_codes = Column(Text, nullable=True)  # JSON list, bcrypt-hashed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    roles = relationship("Role", secondary=user_role, back_populates="users")
    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_admin(self) -> bool:
        """Return True when the user has the admin role."""
        return any(r.name == "admin" for r in (self.roles or []))


class RefreshToken(Base):  # pylint: disable=too-few-public-methods
    """RefreshToken model for handling JWT refresh tokens."""

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    is_valid = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")


class Group(Base):  # pylint: disable=too-few-public-methods
    """Group model for organizing systems."""

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    parent_id = Column(
        Integer, ForeignKey("groups.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    systems = relationship("System", back_populates="group")
    parent = relationship("Group", remote_side=[id], backref="children")


class Credential(Base):  # pylint: disable=too-few-public-methods
    """Credential model — metadata only. Secrets stored in Vault.

    auth_method: "password" or "ssh_key" — describes how to authenticate
    vault_path: path to secret in Vault (auto-generated or custom for grandfathered creds)
    """

    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    auth_method = Column(String(50), nullable=False)  # password, ssh_key
    username = Column(String(255), nullable=True)
    vault_path = Column(String(512), nullable=True)
    sudo_method = Column(String(50), nullable=False, server_default="none")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    systems = relationship("System", back_populates="credentials")


class System(Base):  # pylint: disable=too-few-public-methods
    """System model for managed Linux systems."""

    __tablename__ = "systems"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    # Unique in the database, not only in the route: duplicate-IP rejection is
    # an invariant two concurrent registrations must not be able to race past.
    ip_address = Column(INET, nullable=False, unique=True)
    distro_id = Column(Integer, ForeignKey("distros.id"), nullable=False, index=True)
    os_version = Column(String(50), nullable=False, index=True)
    last_audited = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False)  # Active, Decommissioned
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    credentials_id = Column(Integer, ForeignKey("credentials.id"), nullable=False)
    ssh_security_policy_id = Column(
        Integer, ForeignKey("ssh_security_policies.id"), nullable=True
    )
    # PRA-44: Zero-trust SSH CA deployment status
    ca_trust_deployed = Column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    ca_trust_deployed_at = Column(DateTime, nullable=True)
    # PRA-138: AuthorizedPrincipalsCommand hook + praxis-principals script
    principals_hook_deployed = Column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    principals_hook_deployed_at = Column(DateTime, nullable=True)
    # PRA-150: M13 thin agent identity + lifecycle. Single source of truth is
    # agent_status; transport_preference is operator routing intent.
    # State machine: not_enrolled -> active <-> disabled; {active,disabled} -> revoked (terminal).
    agent_status = Column(
        SAEnum(
            "not_enrolled",
            "active",
            "disabled",
            "revoked",
            name="agent_status_enum",
        ),
        nullable=False,
        default="not_enrolled",
        server_default="not_enrolled",
    )
    agent_cert_serial = Column(String(128), nullable=True, unique=True, index=True)
    agent_cert_fingerprint = Column(String(128), nullable=True)
    agent_cert_expires_at = Column(DateTime, nullable=True)
    agent_revoked_at = Column(DateTime, nullable=True)
    # Operator context for non-terminal status changes (e.g. why disabled).
    # Cleared on re-enable. Distinct from agent_revocation_reason which is
    # paired with agent_revoked_at and survives.
    agent_status_reason = Column(String(255), nullable=True)
    agent_revocation_reason = Column(String(255), nullable=True)
    agent_last_seen_at = Column(DateTime, nullable=True)
    agent_version = Column(String(32), nullable=True)
    transport_preference = Column(
        SAEnum("auto", "ssh", "agent", name="transport_preference_enum"),
        nullable=False,
        default="auto",
        server_default="auto",
    )
    registered_at = Column(DateTime, default=datetime.utcnow)
    registered_by = Column(Integer, ForeignKey("user.id"))
    update_policy = Column(String(50))
    description = Column(Text, nullable=True)
    last_successful_update = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    group = relationship("Group", back_populates="systems")
    credentials = relationship("Credential", back_populates="systems")
    distro = relationship("Distro", back_populates="systems")
    ssh_security_policy = relationship("SSHSecurityPolicy", back_populates="systems")
    packages = relationship(
        "Package", back_populates="system", cascade="all, delete-orphan"
    )
    package_updates = relationship(
        "PackageUpdate", back_populates="system", cascade="all, delete-orphan"
    )
    system_metadata = relationship(
        "SystemMetadata",
        back_populates="system",
        uselist=False,
        cascade="all, delete-orphan",
    )
    # Audits intentionally do NOT cascade-delete: history must survive
    # system removal (FK is ON DELETE SET NULL at the DB level).
    audits = relationship("SystemAudit", back_populates="system")
    security_logs = relationship(
        "SSHSecurityLog", back_populates="system", cascade="all, delete-orphan"
    )
    host_keys = relationship(
        "SSHHostKey", back_populates="system", cascade="all, delete-orphan"
    )
    repo_sources = relationship(
        "RepoSource", back_populates="system", cascade="all, delete-orphan"
    )
    tags = relationship("Tag", secondary=system_tag, back_populates="systems")


class SystemMetadata(Base):  # pylint: disable=too-few-public-methods
    """SystemMetadata model for additional system information."""

    __tablename__ = "system_metadata"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False, unique=True)
    cpu_arch = Column(String(50))
    cpu_cores = Column(Integer)
    memory_total = Column(BigInteger)  # in bytes
    disk_total = Column(BigInteger)  # in bytes
    environment_type = Column(String(50))  # production, staging, etc.
    maintenance_window = Column(String(100))
    owner_contact = Column(String(255))
    location = Column(String(255))
    ssh_port = Column(Integer, default=22)
    last_connection = Column(DateTime)
    connection_status = Column(String(50))
    consecutive_failures = Column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # PRA-313: per-host transport circuit breaker. ``transport_failures`` counts
    # consecutive banner/connect/socket failures (NOT auth failures — those mean
    # the host is reachable). Once it reaches the configured threshold,
    # ``transport_cooldown_until`` is set so normal ops fast-fail without opening a
    # new SSH socket until it elapses; ``last_transport_error`` is the bounded,
    # operator-readable reason. A successful connect (or a reachable-but-auth-failed
    # connect) resets all three.
    transport_failures = Column(Integer, nullable=False, default=0, server_default="0")
    transport_cooldown_until = Column(DateTime, nullable=True)
    last_transport_error = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="system_metadata")


class Package(Base):  # pylint: disable=too-few-public-methods
    """Package model for installed packages on systems."""

    __tablename__ = "packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    name = Column(String(255), nullable=False, index=True)
    installed_version = Column(String(50), nullable=False)
    installation_date = Column(DateTime)
    package_type = Column(String(50))
    is_security_critical = Column(Boolean, default=False)
    is_held = Column(Boolean, default=False, nullable=False, server_default="false")
    last_audited = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="packages")
    updates = relationship(
        "PackageUpdate", back_populates="package", cascade="all, delete-orphan"
    )
    history = relationship(
        "PackageHistory", back_populates="package", cascade="all, delete-orphan"
    )


class PackageUpdate(Base):  # pylint: disable=too-few-public-methods
    """PackageUpdate model for available package updates."""

    __tablename__ = "package_updates"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    package_id = Column(Integer, ForeignKey("packages.id"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    available_version = Column(String(50), nullable=False)
    update_type = Column(String(50), nullable=False)  # security, normal
    discovered_on = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    package = relationship("Package", back_populates="updates")
    system = relationship("System", back_populates="package_updates")


class PackageHistory(Base):  # pylint: disable=too-few-public-methods
    """PackageHistory model for tracking package operations."""

    __tablename__ = "package_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    package_id = Column(Integer, ForeignKey("packages.id"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    operation = Column(String(50), nullable=False)  # install, update, remove
    old_version = Column(String(50))
    new_version = Column(String(50))
    status = Column(String(50), nullable=False, server_default="completed")
    error_message = Column(Text, nullable=True)
    performed_at = Column(DateTime, nullable=False)
    performed_by = Column(Integer, ForeignKey("user.id"))
    job_history_id = Column(Integer, ForeignKey("job_history.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    package = relationship("Package", back_populates="history")
    job = relationship("JobHistory", back_populates="package_operations")


class RepoSource(Base):  # pylint: disable=too-few-public-methods
    """RepoSource model for package repository sources on systems."""

    __tablename__ = "repo_sources"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    name = Column(String(255), nullable=False)
    url = Column(Text, nullable=False)
    repo_type = Column(String(50), nullable=False)  # apt, yum, dnf
    enabled = Column(Boolean, default=True, nullable=False)
    file_path = Column(
        String(500), nullable=True
    )  # e.g. /etc/apt/sources.list.d/x.list
    gpg_key_url = Column(Text, nullable=True)
    components = Column(String(500), nullable=True)  # e.g. "main restricted universe"
    distribution = Column(String(255), nullable=True)  # e.g. "jammy", "focal"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="repo_sources")


class Job(Base):  # pylint: disable=too-few-public-methods
    """Job model for scheduled operations."""

    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    job_type = Column(
        String(50), nullable=False
    )  # update, security_update, audit, package_scan
    schedule = Column(String(100))  # cron expression, null for one-time
    is_recurring = Column(Boolean, default=False)
    status = Column(
        String(50), nullable=False, default="scheduled"
    )  # scheduled, running, completed, failed, cancelled, paused

    # Targeting - flexible: can target specific systems, groups, tags, or all
    target_type = Column(String(50), nullable=False)  # system, group, tag, all
    target_ids = Column(Text)  # JSON array of system_ids, group_ids, or tag_ids
    tag_match_logic = Column(
        String(10), server_default="or"
    )  # "or" or "and" for tag targeting
    package_filter = Column(
        Text
    )  # JSON: {"names": ["openssl"], "keywords": ["lib"], "security_only": true}

    # PRA-101: Concurrency control for parallel system execution
    max_parallel = Column(Integer, nullable=False, default=1, server_default="1")

    last_run = Column(DateTime)
    next_run = Column(DateTime)

    # PRA-81: Job chaining / dependencies
    depends_on_job_id = Column(
        Integer, ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    chain_condition = Column(
        String(50), nullable=False, default="on_success", server_default="on_success"
    )  # on_success, on_complete, on_failure

    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    creator = relationship("User")
    history = relationship(
        "JobHistory", back_populates="job", cascade="all, delete-orphan"
    )
    dependency = relationship(
        "Job", remote_side="Job.id", foreign_keys=[depends_on_job_id]
    )


class JobHistory(Base):  # pylint: disable=too-few-public-methods
    """JobHistory model for tracking job executions."""

    __tablename__ = "job_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    status = Column(String(50), nullable=False)
    result = Column(Text)
    error_message = Column(Text)
    systems_targeted = Column(Integer, default=0)
    systems_completed = Column(Integer, default=0)
    systems_failed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    job = relationship("Job", back_populates="history")
    package_operations = relationship("PackageHistory", back_populates="job")


class SystemAudit(Base):  # pylint: disable=too-few-public-methods
    """SystemAudit model for tracking system changes."""

    __tablename__ = "system_audits"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(
        Integer, ForeignKey("systems.id", ondelete="SET NULL"), nullable=True
    )
    audit_type = Column(String(50), nullable=False)
    changed_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    changed_at = Column(DateTime, nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    operation = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="audits")


class Distro(Base):  # pylint: disable=too-few-public-methods
    """Distro model for Linux distributions."""

    __tablename__ = "distros"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    release_date = Column(Date, nullable=False)
    end_of_life_date = Column(Date, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    systems = relationship("System", back_populates="distro")


class VaultConfig(Base):  # pylint: disable=too-few-public-methods
    """VaultConfig model for storing Vault connection settings.

    Token is read from VAULT_TOKEN env var, not stored in DB.
    """

    __tablename__ = "vault_config"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    is_internal = Column(Boolean, default=True, nullable=False)
    server_url = Column(String(255), nullable=True)  # Only needed for external Vault
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    last_health_check = Column(DateTime, nullable=True)
    health_status = Column(String(50), nullable=True)  # healthy, unhealthy, etc.


class OIDCProvider(Base):  # pylint: disable=too-few-public-methods
    """OIDC identity provider configuration. Single provider at a time."""

    __tablename__ = "oidc_provider"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(
        String(255), nullable=False
    )  # Display name (e.g., "Okta", "Azure AD")
    discovery_url = Column(
        String(1024), nullable=False
    )  # .well-known/openid-configuration
    client_id = Column(String(255), nullable=False)
    client_secret = Column(String(512), nullable=False)
    # Which JWT claim to use for role mapping
    role_claim = Column(String(255), nullable=False, server_default="roles")
    # JSON mapping: claim_value -> praxis_role (e.g., {"admin": "admin", "viewer": "auditor"})
    role_mapping = Column(Text, nullable=True)
    enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OIDCLoginState(Base):  # pylint: disable=too-few-public-methods
    """Pending OIDC login state/nonce (PRA-218).

    The OIDC authorization-code flow generates a ``state`` + ``nonce`` at the
    ``/auth/oidc/login`` step and validates them at ``/auth/oidc/callback``.
    Some deployments can run multiple uvicorn workers, so a process-local dict
    cannot be relied on: the login and callback requests may land on different
    workers. Persisting the state in Postgres makes the flow deterministic
    across workers.

    Rows are single-use: ``consume_state`` deletes the row when it validates,
    so a replayed ``state`` finds nothing. ``expires_at`` bounds the lifetime
    (TTL) and expired rows are rejected and swept opportunistically.

    ``redirect_uri`` is the exact value sent to the IdP at authorize time; the
    callback re-uses it for the token exchange so the two steps always agree
    (PRA-217).
    """

    __tablename__ = "oidc_login_state"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    state = Column(String(128), nullable=False, unique=True, index=True)
    nonce = Column(String(128), nullable=False)
    provider_id = Column(Integer, nullable=False)
    redirect_uri = Column(String(1024), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CommandWhitelist(Base):  # pylint: disable=too-few-public-methods
    """CommandWhitelist model for managing allowed commands."""

    __tablename__ = "command_whitelist"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    command_pattern = Column(String(500), nullable=False)
    is_regex = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    risk_level = Column(String(50), nullable=False)  # low, medium, high, critical
    category = Column(
        String(100), nullable=False
    )  # package_management, system_info, etc.
    requires_sudo = Column(Boolean, default=False, nullable=False)
    requires_approval = Column(
        Boolean, default=False, nullable=False, server_default="false"
    )
    # PRA-129: multi-level approval (N distinct admin approvals)
    required_approvals = Column(Integer, nullable=False, default=1, server_default="1")
    timeout_seconds = Column(Integer, default=30, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Relationships
    distro_commands = relationship(
        "CommandDistroMapping", back_populates="command", cascade="all, delete-orphan"
    )
    validation_logs = relationship(
        "CommandValidationLog", back_populates="command", cascade="all, delete-orphan"
    )


class CommandDistroMapping(Base):  # pylint: disable=too-few-public-methods
    """CommandDistroMapping model for distribution-specific command mappings."""

    __tablename__ = "command_distro_mapping"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    command_id = Column(Integer, ForeignKey("command_whitelist.id"), nullable=False)
    distro_id = Column(Integer, ForeignKey("distros.id"), nullable=False)
    distro_version_pattern = Column(
        String(100), nullable=True
    )  # e.g., ">=18.04", "20.*"
    command_override = Column(
        String(500), nullable=True
    )  # Override command for this distro
    is_supported = Column(Boolean, default=True, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    command = relationship("CommandWhitelist", back_populates="distro_commands")
    distro = relationship("Distro")


class CommandValidationRule(Base):  # pylint: disable=too-few-public-methods
    """CommandValidationRule model for command validation patterns."""

    __tablename__ = "command_validation_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    validation_type = Column(
        String(50), nullable=False
    )  # pattern, blacklist, parameter_check
    pattern = Column(String(1000), nullable=False)
    is_regex = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    severity = Column(String(50), nullable=False)  # info, warning, error, critical
    error_message = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Relationships
    validation_logs = relationship(
        "CommandValidationLog",
        back_populates="validation_rule",
        cascade="all, delete-orphan",
    )


class CommandValidationLog(Base):  # pylint: disable=too-few-public-methods
    """CommandValidationLog model for tracking command validation attempts."""

    __tablename__ = "command_validation_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    command_id = Column(Integer, ForeignKey("command_whitelist.id"), nullable=True)
    validation_rule_id = Column(
        Integer, ForeignKey("command_validation_rules.id"), nullable=True
    )
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    raw_command = Column(String(1000), nullable=False)
    normalized_command = Column(String(1000), nullable=True)
    validation_status = Column(String(50), nullable=False)  # allowed, denied, warning
    validation_reason = Column(Text, nullable=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    session_id = Column(String(255), nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    command = relationship("CommandWhitelist", back_populates="validation_logs")
    validation_rule = relationship(
        "CommandValidationRule", back_populates="validation_logs"
    )
    system = relationship("System")
    user = relationship("User")


class CommandPolicyBaseline(Base):  # pylint: disable=too-few-public-methods
    """Record of shipped command-policy items that initialization has applied.

    Startup initialization installs a baseline of command whitelist entries,
    validation rules, and distro mappings. Without a durable record of what has
    already been installed, initialization cannot tell an item an administrator
    deliberately deleted from an item that was never created, so every restart
    would restore deleted policy outside any request context.

    A row here means the named baseline item has been applied once. Initialization
    never creates that item again, so an administrator deletion is permanent until
    an explicit, audited restoration. The row is deliberately independent of the
    policy row it describes: deleting the policy row must not delete the record
    that it was already installed.

    ``item_key`` is the stable identity initialization matches on: the entry or
    rule name, and ``"<command name>::<distro name>-<distro version>"`` for a
    distro mapping.
    """

    __tablename__ = "command_policy_baseline"
    __table_args__ = (
        UniqueConstraint(
            "item_type", "item_key", name="uq_command_policy_baseline_item"
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    # whitelist_entry, validation_rule, or distro_mapping
    item_type = Column(String(50), nullable=False, index=True)
    item_key = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CommandApproval(Base):  # pylint: disable=too-few-public-methods
    """Approval request for commands that require admin sign-off (PRA-80)."""

    __tablename__ = "command_approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    command = Column(String(1000), nullable=False)
    system_id = Column(
        Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False
    )
    whitelist_entry_id = Column(
        Integer, ForeignKey("command_whitelist.id", ondelete="SET NULL"), nullable=True
    )
    requested_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    decided_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    status = Column(
        String(20), nullable=False, default="pending", server_default="pending"
    )
    comment = Column(Text, nullable=True)
    timeout_seconds = Column(Integer, nullable=True)
    # PRA-129: enforced expiration + multi-level approval
    expires_at = Column(DateTime, nullable=True, index=True)
    required_approvals = Column(Integer, nullable=False, default=1, server_default="1")
    session_id = Column(String(255), nullable=True)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")
    whitelist_entry = relationship("CommandWhitelist")
    requester = relationship("User", foreign_keys=[requested_by])
    decider = relationship("User", foreign_keys=[decided_by])
    votes = relationship(
        "CommandApprovalVote",
        back_populates="approval",
        cascade="all, delete-orphan",
    )


class CommandApprovalVote(Base):  # pylint: disable=too-few-public-methods
    """Per-admin vote on a CommandApproval (PRA-129 multi-level)."""

    __tablename__ = "command_approval_votes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    approval_id = Column(
        Integer,
        ForeignKey("command_approvals.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    decision = Column(String(20), nullable=False)  # approve / reject
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    approval = relationship("CommandApproval", back_populates="votes")
    user = relationship("User")


class PatchApproval(Base):  # pylint: disable=too-few-public-methods
    """Patch-scoped approval request (PRA-161 slice 1a).

    Polymorphic over patch subjects: ``subject_kind`` is one of
    ``policy`` / ``plan`` / ``rollback`` and ``subject_id`` points at
    the corresponding row in that subject's table. Foreign-key
    integrity is enforced at the application layer (no polymorphic FK
    in Postgres); the CHECK constraint on ``subject_kind`` keeps the
    set of allowed kinds locked to migrations.

    Distinct from :class:`CommandApproval` in one critical way: the
    ``patch_approval_service`` does **not** auto-execute on threshold.
    Callers query :func:`get_approval_status` and decide whether to
    proceed. This avoids the command-approval pattern of
    ``_execute_in_background`` becoming part of the trust boundary
    for patch operations.
    """

    __tablename__ = "patch_approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subject_kind = Column(String(32), nullable=False)
    subject_id = Column(Integer, nullable=False)
    status = Column(
        String(20), nullable=False, default="pending", server_default="pending"
    )
    required_approvals = Column(Integer, nullable=False, default=1, server_default="1")
    expires_at = Column(DateTime, nullable=True)
    requested_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    decided_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    requester = relationship("User", foreign_keys=[requested_by])
    decider = relationship("User", foreign_keys=[decided_by])
    votes = relationship(
        "PatchApprovalVote",
        back_populates="approval",
        cascade="all, delete-orphan",
    )

    # Mirror the alembic migration constraints/indexes so that
    # ``Base.metadata.create_all()`` (used by the test conftest)
    # produces the same schema as ``alembic upgrade head``.
    __table_args__ = (
        CheckConstraint(
            "subject_kind IN ('policy', 'plan', 'rollback')",
            name="patch_approvals_subject_kind_valid",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired')",
            name="patch_approvals_status_valid",
        ),
        CheckConstraint(
            "required_approvals >= 1",
            name="patch_approvals_required_approvals_positive",
        ),
        Index(
            "ix_patch_approvals_subject",
            "subject_kind",
            "subject_id",
        ),
        Index(
            "ix_patch_approvals_pending_expires_at",
            "expires_at",
            postgresql_where=sa_text("status = 'pending' AND expires_at IS NOT NULL"),
        ),
    )


class PatchApprovalVote(Base):  # pylint: disable=too-few-public-methods
    """Per-admin vote on a :class:`PatchApproval` (PRA-161 slice 1a)."""

    __tablename__ = "patch_approval_votes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    approval_id = Column(
        Integer,
        ForeignKey("patch_approvals.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    decision = Column(String(20), nullable=False)  # approve / reject
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    approval = relationship("PatchApproval", back_populates="votes")
    user = relationship("User")

    __table_args__ = (
        CheckConstraint(
            "decision IN ('approve', 'reject')",
            name="patch_approval_votes_decision_valid",
        ),
        UniqueConstraint(
            "approval_id",
            "user_id",
            name="uq_patch_approval_votes_one_per_user",
        ),
    )


class PatchPolicy(Base):  # pylint: disable=too-few-public-methods
    """Declarative patch policy (PRA-161 slice 1b).

    Defines what a future :class:`PatchPlan` may select (scope),
    under what governance (approval), and how it rolls out
    (immediate vs staged via rings; ring tables live in PRA-162).

    Two MaintenanceWindow references:

    * ``maintenance_window_id`` — when patches may apply.
    * ``reboot_window_id`` — when post-patch reboots may occur
      (consumed later by PRA-172).

    Both nullable; both ``ON DELETE SET NULL`` so deleting a
    window does not cascade-delete the policy.

    Bindings (host / static group / smart group / fleet default)
    and the effective-policy resolver land in slice 1c.
    """

    __tablename__ = "patch_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    scope_kind = Column(String(32), nullable=False)
    scope_packages = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    reboot_policy = Column(String(32), nullable=False)
    reboot_window_id = Column(
        Integer,
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
        nullable=True,
    )
    maintenance_window_id = Column(
        Integer,
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
        nullable=True,
    )
    requires_approval = Column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    required_approvals = Column(Integer, nullable=False, default=1, server_default="1")
    rollout_cadence = Column(String(32), nullable=False)
    failure_policy = Column(String(32), nullable=False)
    enabled = Column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    is_fleet_default = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=sa_text("false"),
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    creator = relationship("User", foreign_keys=[created_by])
    reboot_window = relationship("MaintenanceWindow", foreign_keys=[reboot_window_id])
    maintenance_window = relationship(
        "MaintenanceWindow", foreign_keys=[maintenance_window_id]
    )

    # Mirror the alembic migration constraints so that
    # ``Base.metadata.create_all()`` produces the same schema as
    # ``alembic upgrade head`` (lesson learned in slice 1a-a).
    __table_args__ = (
        UniqueConstraint("slug", name="uq_patch_policies_slug"),
        CheckConstraint(
            "scope_kind IN ('security_only', 'full', "
            "'package_allowlist', 'package_denylist')",
            name="patch_policies_scope_kind_valid",
        ),
        CheckConstraint(
            "reboot_policy IN ('never', 'if_required', 'always')",
            name="patch_policies_reboot_policy_valid",
        ),
        CheckConstraint(
            "rollout_cadence IN ('immediate', 'staged')",
            name="patch_policies_rollout_cadence_valid",
        ),
        CheckConstraint(
            "failure_policy IN ('continue', 'pause_fleet')",
            name="patch_policies_failure_policy_valid",
        ),
        CheckConstraint(
            "required_approvals >= 1",
            name="patch_policies_required_approvals_positive",
        ),
        Index(
            "uq_patch_policies_single_fleet_default",
            "is_fleet_default",
            unique=True,
            postgresql_where=sa_text("is_fleet_default = true"),
        ),
    )


class PatchPolicyHostBinding(Base):  # pylint: disable=too-few-public-methods
    """Direct host → patch policy binding (PRA-161 slice 1c).

    Highest-precedence source in the (slice-1d) effective-policy
    resolver. ``ON DELETE CASCADE`` from both sides so deleting
    either the policy or the host removes the binding.
    """

    __tablename__ = "patch_policy_host_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("patch_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    policy = relationship("PatchPolicy", foreign_keys=[policy_id])
    system = relationship("System", foreign_keys=[system_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "system_id",
            name="uq_patch_policy_host_bindings_policy_system",
        ),
        Index("ix_patch_policy_host_bindings_system", "system_id"),
        Index("ix_patch_policy_host_bindings_policy", "policy_id"),
    )


class PatchPolicyGroupBinding(Base):  # pylint: disable=too-few-public-methods
    """Static group → patch policy binding (PRA-161 slice 1c).

    Second-precedence source after direct host bindings.
    """

    __tablename__ = "patch_policy_group_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("patch_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    policy = relationship("PatchPolicy", foreign_keys=[policy_id])
    group = relationship("Group", foreign_keys=[group_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "group_id",
            name="uq_patch_policy_group_bindings_policy_group",
        ),
        Index("ix_patch_policy_group_bindings_group", "group_id"),
        Index("ix_patch_policy_group_bindings_policy", "policy_id"),
    )


class PatchPolicySmartGroupBinding(Base):  # pylint: disable=too-few-public-methods
    """Smart group → patch policy binding (PRA-161 slice 1c).

    Third-precedence source. Useful immediately even without
    ``patch.*`` smart-group predicates (slice 1e) because a smart
    group built from ``facts.*`` / ``lifecycle.*`` / ``profile.*``
    predicates can be bound to a patch policy and the resolver
    (slice 1d) will walk ``smart_group_memberships`` to find member
    hosts.
    """

    __tablename__ = "patch_policy_smart_group_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("patch_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    policy = relationship("PatchPolicy", foreign_keys=[policy_id])
    smart_group = relationship("SmartGroup", foreign_keys=[smart_group_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "smart_group_id",
            name="uq_patch_policy_smart_group_bindings_policy_smart_group",
        ),
        Index("ix_patch_policy_smart_group_bindings_smart_group", "smart_group_id"),
        Index("ix_patch_policy_smart_group_bindings_policy", "policy_id"),
    )


class PatchRing(Base):  # pylint: disable=too-few-public-methods
    """First-class patch ring (PRA-162 slice 1).

    Defines a stage in a staged rollout. ``sort_order`` is unique
    and ``>= 1`` so the canary→pilot→prod default seed has a stable
    position vocabulary. Rings do **not** execute updates — that's
    PRA-171. Promotion gates land in a later PRA-162 slice.

    Membership lives in three sibling tables (host / static-group /
    smart-group) parallel to the PRA-161 patch-policy bindings. The
    effective-ring resolver lives in slice 2; this slice ships
    binding rows only.
    """

    __tablename__ = "patch_rings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    sort_order = Column(Integer, nullable=False)
    enabled = Column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint("slug", name="uq_patch_rings_slug"),
        UniqueConstraint("sort_order", name="uq_patch_rings_sort_order"),
        CheckConstraint(
            "sort_order >= 1",
            name="patch_rings_sort_order_positive",
        ),
    )


class PatchRingHostBinding(Base):  # pylint: disable=too-few-public-methods
    """Direct host → patch ring binding (PRA-162 slice 1)."""

    __tablename__ = "patch_ring_host_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ring = relationship("PatchRing", foreign_keys=[ring_id])
    system = relationship("System", foreign_keys=[system_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "ring_id",
            "system_id",
            name="uq_patch_ring_host_bindings_ring_system",
        ),
        Index("ix_patch_ring_host_bindings_ring", "ring_id"),
        Index("ix_patch_ring_host_bindings_system", "system_id"),
    )


class PatchRingGroupBinding(Base):  # pylint: disable=too-few-public-methods
    """Static group → patch ring binding (PRA-162 slice 1)."""

    __tablename__ = "patch_ring_group_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ring = relationship("PatchRing", foreign_keys=[ring_id])
    group = relationship("Group", foreign_keys=[group_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "ring_id",
            "group_id",
            name="uq_patch_ring_group_bindings_ring_group",
        ),
        Index("ix_patch_ring_group_bindings_ring", "ring_id"),
        Index("ix_patch_ring_group_bindings_group", "group_id"),
    )


class PatchRingSmartGroupBinding(Base):  # pylint: disable=too-few-public-methods
    """Smart group → patch ring binding (PRA-162 slice 1)."""

    __tablename__ = "patch_ring_smart_group_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ring = relationship("PatchRing", foreign_keys=[ring_id])
    smart_group = relationship("SmartGroup", foreign_keys=[smart_group_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "ring_id",
            "smart_group_id",
            name="uq_patch_ring_smart_group_bindings_ring_smart_group",
        ),
        Index("ix_patch_ring_smart_group_bindings_smart_group", "smart_group_id"),
        Index("ix_patch_ring_smart_group_bindings_ring", "ring_id"),
    )


class PatchRingGateDefinition(Base):  # pylint: disable=too-few-public-methods
    """Promotion gate declared on a patch ring (PRA-162 slice 4).

    A gate names a ``signal_key`` the ring expects to see evidence
    for before it can be promoted. Operators (or future PRA-171/172
    writers via ``patch_ring_gate_signals.source_kind``) record
    matching signals; promotion readiness is computed from those
    stored rows. This slice does not run probes or execute anything.

    ``gate_kind`` ∈ ``{boolean, threshold}``. ``comparator`` is
    required for ``threshold`` and ignored for ``boolean``.
    ``parameters`` is a JSONB envelope:

    * boolean: ``{"expected": <bool>}`` (default ``true`` if null)
    * threshold: ``{"threshold": <number>}``
    """

    __tablename__ = "patch_ring_gate_definitions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    signal_key = Column(String(128), nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    gate_kind = Column(String(32), nullable=False)
    comparator = Column(String(8), nullable=True)
    parameters = Column(JSONB, nullable=True)
    required = Column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    enabled = Column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ring = relationship("PatchRing", foreign_keys=[ring_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "ring_id",
            "signal_key",
            name="uq_patch_ring_gate_definitions_ring_signal_key",
        ),
        CheckConstraint(
            "gate_kind IN ('boolean', 'threshold')",
            name="patch_ring_gate_definitions_gate_kind_vocab",
        ),
        CheckConstraint(
            "comparator IS NULL OR comparator IN "
            "('eq', 'ne', 'gt', 'gte', 'lt', 'lte')",
            name="patch_ring_gate_definitions_comparator_vocab",
        ),
        Index("ix_patch_ring_gate_definitions_ring", "ring_id"),
        Index(
            "ix_patch_ring_gate_definitions_ring_enabled",
            "ring_id",
            "enabled",
        ),
    )


class PatchRingGateSignal(Base):  # pylint: disable=too-few-public-methods
    """Stored gate signal evidence (PRA-162 slice 4).

    Match-by-``signal_key`` with the corresponding gate definition
    on the ring. The optional ``gate_definition_id`` FK is
    ``ON DELETE SET NULL`` so historical signal rows survive a
    definition removal — promotion-readiness will treat them as
    orphaned but the audit trail stays intact.

    ``source_kind`` reserves room for PRA-171/172 writers; this slice
    only ships ``manual`` from the API surface, but the CHECK
    constraint admits the future values.
    """

    __tablename__ = "patch_ring_gate_signals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    gate_definition_id = Column(
        Integer,
        ForeignKey("patch_ring_gate_definitions.id", ondelete="SET NULL"),
        nullable=True,
    )
    signal_key = Column(String(128), nullable=False)
    status = Column(String(16), nullable=False)
    value = Column(JSONB, nullable=True)
    details = Column(JSONB, nullable=True)
    source_kind = Column(String(32), nullable=False)
    source_ref_kind = Column(String(64), nullable=True)
    source_ref_id = Column(String(128), nullable=True)
    observed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ring = relationship("PatchRing", foreign_keys=[ring_id])
    gate_definition = relationship(
        "PatchRingGateDefinition", foreign_keys=[gate_definition_id]
    )
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        CheckConstraint(
            "status IN ('pass', 'fail')",
            name="patch_ring_gate_signals_status_vocab",
        ),
        CheckConstraint(
            "source_kind IN ('manual', 'execution', 'reboot', 'probe', 'external')",
            name="patch_ring_gate_signals_source_kind_vocab",
        ),
        Index(
            "ix_patch_ring_gate_signals_ring_signal_observed",
            "ring_id",
            "signal_key",
            sa_text("observed_at DESC"),
        ),
        Index(
            "ix_patch_ring_gate_signals_definition",
            "gate_definition_id",
        ),
    )


class PatchPolicyRingBinding(Base):  # pylint: disable=too-few-public-methods
    """Patch policy → patch ring binding (PRA-162 slice 3).

    Joins a staged patch policy to the rings it is allowed to roll
    out across. Immediate policies do not use ring sets; the bind
    service rejects them at the application layer. New bindings to a
    disabled ring are rejected; existing bindings to a later-disabled
    ring stay visible so operators can fix them.
    """

    __tablename__ = "patch_policy_ring_bindings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("patch_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    ring_id = Column(
        Integer,
        ForeignKey("patch_rings.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    policy = relationship("PatchPolicy", foreign_keys=[policy_id])
    ring = relationship("PatchRing", foreign_keys=[ring_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "ring_id",
            name="uq_patch_policy_ring_bindings_policy_ring",
        ),
        Index("ix_patch_policy_ring_bindings_policy", "policy_id"),
        Index("ix_patch_policy_ring_bindings_ring", "ring_id"),
    )


class PatchAdvisory(Base):  # pylint: disable=too-few-public-methods
    """Native distribution security/bugfix advisory (PRA-163 slice 1).

    One row per ``(source_kind, source_advisory_id)``. Source identity
    such as ``USN-7234-1`` or ``RHSA-2024:1234`` is preserved — never
    collapsed into a single ambiguous string. Per-release fixed-version
    targets live in :class:`PatchAdvisoryFixedPackage` and are joined
    by PRA-164 host-applicability lookups.

    ``digest`` is the sha256 of the canonical-JSON ``raw`` payload and
    drives refresh detection: a re-import whose digest matches the
    stored row is a true no-op (no audit, no row write).

    Vocabulary CHECKs mirror the alembic migration so
    ``Base.metadata.create_all()`` and ``alembic upgrade head`` produce
    the same schema (PRA-161 slice 1a-a parity rule carry-forward).

    PRA-161 ``scope_kind=security_only`` semantics translate to
    ``advisory_class='security'`` — PRA-164 will use that pairing for
    plan generation.
    """

    __tablename__ = "patch_advisories"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_kind = Column(String(32), nullable=False)
    source_advisory_id = Column(String(128), nullable=False)
    advisory_class = Column(String(32), nullable=False)
    severity = Column(String(32), nullable=False)
    title = Column(String(512), nullable=False)
    summary = Column(Text, nullable=True)
    distro_family = Column(String(32), nullable=False)
    published_at = Column(DateTime, nullable=True)
    source_updated_at = Column(DateTime, nullable=True)
    cve_ids = Column(JSONB, nullable=True)
    external_refs = Column(JSONB, nullable=True)
    raw = Column(JSONB, nullable=True)
    digest = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    fixed_packages = relationship(
        "PatchAdvisoryFixedPackage",
        cascade="all, delete-orphan",
        back_populates="advisory",
    )

    __table_args__ = (
        UniqueConstraint(
            "source_kind",
            "source_advisory_id",
            name="uq_patch_advisories_source_id",
        ),
        CheckConstraint(
            "source_kind IN ('ubuntu_usn', 'debian_security', 'redhat_updateinfo')",
            name="patch_advisories_source_kind_vocab",
        ),
        CheckConstraint(
            "advisory_class IN ('security', 'bugfix', 'enhancement', 'other')",
            name="patch_advisories_advisory_class_vocab",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'negligible', "
            "'unknown')",
            name="patch_advisories_severity_vocab",
        ),
        CheckConstraint(
            "distro_family IN ('debian', 'rhel')",
            name="patch_advisories_distro_family_vocab",
        ),
        Index(
            "ix_patch_advisories_source_kind_severity",
            "source_kind",
            "severity",
        ),
        Index("ix_patch_advisories_advisory_class", "advisory_class"),
        Index("ix_patch_advisories_distro_family", "distro_family"),
    )


class PatchAdvisoryFixedPackage(Base):  # pylint: disable=too-few-public-methods
    """Per-release fixed-version target on an advisory (PRA-163 slice 1).

    The PRA-164 applicability driver: a host with
    ``(distro_id, distro_release, installed_package_name)`` joins this
    table to discover candidate advisories. ``fixed_version`` is
    nullable so an advisory that names a vulnerable package without
    a published fix is still representable.

    Replace-all on advisory refresh (delete-then-insert by advisory_id)
    keeps idempotency simple and avoids per-row diff state.
    """

    __tablename__ = "patch_advisory_fixed_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    advisory_id = Column(
        Integer,
        ForeignKey("patch_advisories.id", ondelete="CASCADE"),
        nullable=False,
    )
    distro_id = Column(String(32), nullable=False)
    distro_release = Column(String(64), nullable=False)
    package_name = Column(String(255), nullable=False)
    fixed_version = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    advisory = relationship("PatchAdvisory", back_populates="fixed_packages")

    __table_args__ = (
        UniqueConstraint(
            "advisory_id",
            "distro_id",
            "distro_release",
            "package_name",
            name="uq_patch_advisory_fixed_packages_target",
        ),
        Index(
            "ix_patch_advisory_fixed_packages_target",
            "distro_id",
            "distro_release",
            "package_name",
        ),
        Index("ix_patch_advisory_fixed_packages_advisory", "advisory_id"),
    )


class PatchAdvisoryImport(Base):  # pylint: disable=too-few-public-methods
    """Per-run summary of a native-source advisory import (PRA-163 slice 1).

    Records what was attempted, what happened, and how counts broke
    down. Operators read this table to see import history without
    parsing thousands of per-advisory audit rows.

    ``status`` ∈ ``{success, partial, failed}``. ``partial`` covers
    runs where some payloads imported and some failed with
    per-payload errors recorded in ``error_details``.
    """

    __tablename__ = "patch_advisory_imports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_kind = Column(String(32), nullable=False)
    status = Column(String(16), nullable=False)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    imported_count = Column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    refreshed_count = Column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    unchanged_count = Column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    error_count = Column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    error_details = Column(JSONB, nullable=True)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        CheckConstraint(
            "source_kind IN ('ubuntu_usn', 'debian_security', 'redhat_updateinfo')",
            name="patch_advisory_imports_source_kind_vocab",
        ),
        CheckConstraint(
            "status IN ('success', 'partial', 'failed')",
            name="patch_advisory_imports_status_vocab",
        ),
        Index(
            "ix_patch_advisory_imports_source_started",
            "source_kind",
            sa_text("started_at DESC"),
        ),
    )


class PatchAdvisoryHostApplicability(Base):  # pylint: disable=too-few-public-methods
    """Per-(host, advisory, package) materialized applicability state
    (PRA-163 slice 2).

    Written by ``patch_advisory_service.compute_host_applicability``,
    which joins host facts (``HostFacts.distro_id_facts`` /
    ``HostFacts.distro_release``) and installed packages
    (``Package.name`` / ``Package.installed_version``) against PRA-163
    Slice 1 ``patch_advisory_fixed_packages`` rows. Per-host
    replace-all keeps the row set deterministic; ``state`` covers the
    four classifications PRA-164 plan generation needs:

    * ``applicable`` — package installed, fix available but not yet
      applied (or no fix published yet).
    * ``fixed`` — package installed, version meets or exceeds the
      published fix.
    * ``not_applicable`` — advisory targets the host's
      ``(distro_id, distro_release)`` but the package isn't installed.
    * ``unknown`` — host facts don't allow a deterministic decision
      (version comparison failed, installed_version missing, etc.).

    ``fixed_package_id`` is ``ON DELETE SET NULL`` so a Slice 1
    refresh that drops a per-release target preserves the historical
    applicability row's audit trail; ``advisory_id`` is CASCADE so
    deleting an advisory drops its applicability rows.

    ``evaluated_at`` is set only when the resolver actually writes
    the row, so a no-op recompute does not bump it.
    """

    __tablename__ = "patch_advisory_host_applicability"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    advisory_id = Column(
        Integer,
        ForeignKey("patch_advisories.id", ondelete="CASCADE"),
        nullable=False,
    )
    fixed_package_id = Column(
        Integer,
        ForeignKey("patch_advisory_fixed_packages.id", ondelete="SET NULL"),
        nullable=True,
    )
    package_name = Column(String(255), nullable=False)
    installed_version = Column(String(255), nullable=True)
    required_version = Column(String(255), nullable=True)
    state = Column(String(32), nullable=False)
    reason = Column(String(255), nullable=True)
    evaluated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    system = relationship("System", foreign_keys=[system_id])
    advisory = relationship("PatchAdvisory", foreign_keys=[advisory_id])
    fixed_package = relationship(
        "PatchAdvisoryFixedPackage", foreign_keys=[fixed_package_id]
    )

    __table_args__ = (
        UniqueConstraint(
            "system_id",
            "advisory_id",
            "package_name",
            name="uq_patch_advisory_host_applicability_target",
        ),
        CheckConstraint(
            "state IN ('applicable', 'fixed', 'not_applicable', 'unknown')",
            name="patch_advisory_host_applicability_state_vocab",
        ),
        Index(
            "ix_patch_advisory_host_applicability_system_state",
            "system_id",
            "state",
        ),
        Index(
            "ix_patch_advisory_host_applicability_advisory",
            "advisory_id",
        ),
    )


class PatchUpdatePlan(Base):  # pylint: disable=too-few-public-methods
    """Dry-run patch update plan (PRA-164 slice 1).

    Audit-grade snapshot of an in-flight rollout: captures the source
    policy, the ring sequence the policy was bound to at draft time,
    the caller's request envelope, and any plan-level structured
    block reasons. Hosts and their wave assignments live in
    :class:`PatchUpdatePlanHost`. The plan does NOT execute anything
    in this slice — execution is PRA-171 and later.

    The ``policy_id`` FK is ``ON DELETE RESTRICT`` so a policy whose
    *active* plans still reference it cannot disappear out from under
    the audit trail. It is nullable (PRA-355): an admin deleting a
    policy whose only remaining links are archived/retired plans
    detaches those plans (``policy_id`` → NULL) rather than destroying
    them — ``policy_snapshot`` preserves the policy identity for the
    tombstone. The two MaintenanceWindow FKs are ``SET NULL`` so a
    later window cleanup does not cascade-delete the plan.

    PRA-355 archive/retire: ``archived_at`` is the soft-delete marker.
    Archived plans keep every row (hosts, approvals, executions, reboot,
    rollback, selected-package evidence) and stay queryable/exportable
    from audit surfaces, but are hidden from normal operator lists and
    selectors. ``state`` remains the plan's last operational state
    (the tombstone's ``prior_state``); archived is an orthogonal axis.
    """

    __tablename__ = "patch_update_plans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("patch_policies.id", ondelete="RESTRICT"),
        nullable=True,
    )
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    state = Column(String(32), nullable=False)
    scheduled_start_at = Column(DateTime, nullable=True)
    maintenance_window_id = Column(
        Integer,
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
        nullable=True,
    )
    reboot_window_id = Column(
        Integer,
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
        nullable=True,
    )
    policy_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    ring_sequence_snapshot = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    request_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    block_reasons = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    # PRA-355 archive/retire tombstone fields. archived_at is the
    # soft-delete marker; archived_by/archive_reason record who retired
    # the plan and why. archived_by is SET NULL so removing a user does
    # not cascade-delete the tombstone.
    archived_at = Column(DateTime, nullable=True)
    archived_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    archive_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    policy = relationship("PatchPolicy", foreign_keys=[policy_id])
    maintenance_window = relationship(
        "MaintenanceWindow", foreign_keys=[maintenance_window_id]
    )
    reboot_window = relationship("MaintenanceWindow", foreign_keys=[reboot_window_id])
    creator = relationship("User", foreign_keys=[created_by])
    archiver = relationship("User", foreign_keys=[archived_by])
    hosts = relationship(
        "PatchUpdatePlanHost",
        back_populates="plan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "state IN ('draft', 'awaiting_approval', 'approved', "
            "'scheduled', 'blocked', 'superseded', 'canceled')",
            name="patch_update_plans_state_vocab",
        ),
        Index("ix_patch_update_plans_policy", "policy_id"),
        Index("ix_patch_update_plans_state", "state"),
        Index("ix_patch_update_plans_archived_at", "archived_at"),
    )


class PatchUpdatePlanHost(Base):  # pylint: disable=too-few-public-methods
    """Per-host wave assignment for a :class:`PatchUpdatePlan`.

    Snapshots the effective patch policy, effective ring (or the
    no-ring/conflict reason), the wave index the host belongs to
    (``0`` for immediate-cadence policies, ring-sort-derived for
    staged), the effective content-profile context, and any
    structured per-host block reasons.

    ``system_id`` is ``ON DELETE SET NULL`` so historical plan rows
    survive a system being removed; the snapshot columns preserve
    the host identity for the audit trail.
    """

    __tablename__ = "patch_update_plan_hosts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    plan_id = Column(
        Integer,
        ForeignKey("patch_update_plans.id", ondelete="CASCADE"),
        nullable=False,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True,
    )
    system_hostname_snapshot = Column(String(255), nullable=True)
    policy_id_snapshot = Column(Integer, nullable=True)
    policy_slug_snapshot = Column(String(64), nullable=True)
    policy_resolution_kind = Column(String(32), nullable=False)
    ring_id_snapshot = Column(Integer, nullable=True)
    ring_slug_snapshot = Column(String(64), nullable=True)
    ring_name_snapshot = Column(String(128), nullable=True)
    ring_sort_order_snapshot = Column(Integer, nullable=True)
    ring_source_tier = Column(String(32), nullable=True)
    ring_resolution_status = Column(String(32), nullable=False)
    wave_index = Column(Integer, nullable=False)
    content_profile_state = Column(String(32), nullable=False)
    content_profile_id_snapshot = Column(Integer, nullable=True)
    content_profile_slug_snapshot = Column(String(64), nullable=True)
    content_profile_display_name_snapshot = Column(String(128), nullable=True)
    content_profile_package_family_snapshot = Column(String(8), nullable=True)
    content_profile_conflict_snapshot = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    state = Column(String(32), nullable=False)
    block_reasons = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # Slice 2: per-host count rollup of selected-package preview rows
    # ({"selected": N, "excluded": N, "unresolvable": N,
    # "inventory_missing": bool}). Nullable so pre-Slice-2 rows stay
    # readable; refresh populates it for every ``planned`` host.
    selection_summary = Column(JSONB, nullable=True)
    # Slice 3: per-host count rollup of preflight snapshot rows
    # ({"available": N, "unavailable": N, "profile_missing": N,
    # "not_applicable": N, "installed_drift_count": N}). Nullable so
    # pre-Slice-3 rows stay readable; refresh populates it for every
    # ``planned`` host with selected packages.
    preflight_summary = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    plan = relationship("PatchUpdatePlan", back_populates="hosts")
    system = relationship("System", foreign_keys=[system_id])
    selected_packages = relationship(
        "PatchUpdatePlanSelectedPackage",
        back_populates="plan_host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    preflight_snapshots = relationship(
        "PatchUpdatePlanPreflightSnapshot",
        back_populates="plan_host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "plan_id",
            "system_id",
            name="uq_patch_update_plan_hosts_plan_system",
        ),
        CheckConstraint(
            "state IN ('planned', 'blocked')",
            name="patch_update_plan_hosts_state_vocab",
        ),
        CheckConstraint(
            "policy_resolution_kind IN ('direct_host', 'static_group', "
            "'smart_group', 'fleet_default', 'no_policy')",
            name="patch_update_plan_hosts_policy_resolution_kind_vocab",
        ),
        CheckConstraint(
            "content_profile_state IN ('resolved', 'no_profile', 'conflict')",
            name="patch_update_plan_hosts_content_profile_state_vocab",
        ),
        CheckConstraint(
            "ring_resolution_status IN ('resolved', 'no_ring', 'conflict', "
            "'not_applicable')",
            name="patch_update_plan_hosts_ring_resolution_status_vocab",
        ),
        CheckConstraint(
            "wave_index >= 0",
            name="patch_update_plan_hosts_wave_index_nonneg",
        ),
        Index(
            "ix_patch_update_plan_hosts_plan_wave",
            "plan_id",
            "wave_index",
        ),
        Index("ix_patch_update_plan_hosts_state", "state"),
        Index("ix_patch_update_plan_hosts_system", "system_id"),
    )


class PatchUpdatePlanSelectedPackage(Base):  # pylint: disable=too-few-public-methods
    """Per-host package/advisory selection preview row (PRA-164 slice 2).

    Materialized once per :class:`PatchUpdatePlanHost` whose state is
    ``planned``. Reads existing DB facts only — ``Package`` /
    ``PackageUpdate`` / ``PatchAdvisoryHostApplicability`` — and never
    invokes a package manager, SSH, or live facts collection.

    ``advisory_id_snapshot`` is FK ``ON DELETE SET NULL`` so historical
    preview rows survive an advisory refresh that drops the source
    advisory. The advisory metadata snapshot columns are populated
    together with the FK so the operator UI can render severity
    without a join.

    ``package_name = ''`` is the sentinel for the per-host
    ``inventory_missing`` placeholder row (one per host, enforced by
    the partial unique on ``advisory_id_snapshot IS NULL``).
    """

    __tablename__ = "patch_update_plan_selected_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    plan_host_id = Column(
        Integer,
        ForeignKey("patch_update_plan_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_name = Column(String(255), nullable=False)
    installed_version_snapshot = Column(String(255), nullable=True)
    available_version_snapshot = Column(String(255), nullable=True)
    advisory_id_snapshot = Column(
        Integer,
        ForeignKey("patch_advisories.id", ondelete="SET NULL"),
        nullable=True,
    )
    advisory_source_kind_snapshot = Column(String(32), nullable=True)
    advisory_class_snapshot = Column(String(32), nullable=True)
    advisory_severity_snapshot = Column(String(32), nullable=True)
    selection_reason = Column(String(48), nullable=False)
    state = Column(String(32), nullable=False)
    details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    plan_host = relationship("PatchUpdatePlanHost", back_populates="selected_packages")
    advisory = relationship("PatchAdvisory", foreign_keys=[advisory_id_snapshot])

    __table_args__ = (
        UniqueConstraint(
            "plan_host_id",
            "package_name",
            "advisory_id_snapshot",
            name="uq_patch_update_plan_selected_packages_target",
        ),
        CheckConstraint(
            "selection_reason IN ('policy_full', 'policy_security_advisory', "
            "'policy_allowlist_match', 'policy_denylist_excluded', "
            "'policy_denylist_default_select', 'no_available_update', "
            "'inventory_missing')",
            name="patch_update_plan_selected_packages_reason_vocab",
        ),
        CheckConstraint(
            "state IN ('selected', 'excluded', 'unresolvable')",
            name="patch_update_plan_selected_packages_state_vocab",
        ),
        Index(
            "uq_patch_update_plan_selected_packages_no_advisory",
            "plan_host_id",
            "package_name",
            unique=True,
            postgresql_where=sa_text("advisory_id_snapshot IS NULL"),
        ),
        Index(
            "ix_patch_update_plan_selected_packages_plan_host",
            "plan_host_id",
        ),
        Index(
            "ix_patch_update_plan_selected_packages_state",
            "state",
        ),
        Index(
            "ix_patch_update_plan_selected_packages_plan_host_state",
            "plan_host_id",
            "state",
        ),
    )


class PatchUpdatePlanPreflightSnapshot(Base):  # pylint: disable=too-few-public-methods
    """Per-(host, package) preflight snapshot row (PRA-164 slice 3).

    Materialized once per ``planned`` host's selected-package set
    after Slice 2 selection completes. Captures (a) the
    moment-in-time installed version of every selected package and
    (b) the strict version-level content-availability verdict
    against the host's effective content profile / mirror set.

    ``content_availability_state`` covers all four spec states:
    ``available`` / ``unavailable`` / ``profile_missing`` /
    ``not_applicable``. ``package_manager_family_snapshot`` is
    derived from ``HostFacts.package_manager`` /
    ``HostFacts.distro_id_facts`` and stays inside the
    apt/dnf/unknown enum.

    Refresh deletes parent ``PatchUpdatePlanHost`` rows with
    synchronize_session=False; the FK CASCADE on ``plan_host_id``
    removes stale preflight rows at the DB layer.
    """

    __tablename__ = "patch_update_plan_preflight_snapshots"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    plan_host_id = Column(
        Integer,
        ForeignKey("patch_update_plan_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_name = Column(String(255), nullable=False)
    installed_version_at_preflight = Column(String(255), nullable=True)
    package_manager_family_snapshot = Column(String(16), nullable=False)
    content_availability_state = Column(String(32), nullable=False)
    availability_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    evaluated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    plan_host = relationship(
        "PatchUpdatePlanHost", back_populates="preflight_snapshots"
    )

    __table_args__ = (
        UniqueConstraint(
            "plan_host_id",
            "package_name",
            name="uq_patch_update_plan_preflight_snapshots_target",
        ),
        CheckConstraint(
            "package_manager_family_snapshot IN ('apt', 'dnf', 'unknown')",
            name="patch_update_plan_preflight_snapshots_family_vocab",
        ),
        CheckConstraint(
            "content_availability_state IN ('available', 'unavailable', "
            "'profile_missing', 'not_applicable')",
            name="patch_update_plan_preflight_snapshots_state_vocab",
        ),
        Index(
            "ix_patch_update_plan_preflight_snapshots_plan_host",
            "plan_host_id",
        ),
        Index(
            "ix_patch_update_plan_preflight_snapshots_plan_host_state",
            "plan_host_id",
            "content_availability_state",
        ),
    )


class PatchUpdatePlanApproval(Base):  # pylint: disable=too-few-public-methods
    """Plan ↔ patch-approval link (PRA-164 slice 4).

    Joins :class:`PatchUpdatePlan` rows to PRA-161
    :class:`PatchApproval` rows so the plan service can answer
    "is this plan approved?" with one trivial join. Approval
    semantics remain owned by ``patch_approval_service`` (PRA-161
    lock #1: never auto-execute); this table is a navigation index.

    ``plan_id`` is FK CASCADE so deleting a plan cleans its link
    rows automatically. ``approval_id`` is FK RESTRICT so the
    audit trail cannot vanish out from under a plan that
    references it; operators must explicitly cancel/reject the
    approval row before it can be removed.
    """

    __tablename__ = "patch_update_plan_approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    plan_id = Column(
        Integer,
        ForeignKey("patch_update_plans.id", ondelete="CASCADE"),
        nullable=False,
    )
    approval_id = Column(
        Integer,
        ForeignKey("patch_approvals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    requested_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    requested_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    plan = relationship("PatchUpdatePlan", foreign_keys=[plan_id])
    approval = relationship("PatchApproval", foreign_keys=[approval_id])
    requester = relationship("User", foreign_keys=[requested_by])

    __table_args__ = (
        UniqueConstraint(
            "plan_id",
            "approval_id",
            name="uq_patch_update_plan_approvals_target",
        ),
        Index(
            "ix_patch_update_plan_approvals_plan",
            "plan_id",
        ),
    )


class PatchUpdateExecution(Base):  # pylint: disable=too-few-public-methods
    """Execution-run substrate for an approved/scheduled plan (PRA-171 slice 1).

    Slice 1 only proves the safety gate, state vocabulary, host
    materialization, metadata-only controls, and progress contract.
    Future PRA-171 slices wire per-host package-manager dispatch on
    top of this row. NO package execution, SSH, agent ops, package
    history mutation, reboot, rollback, mirror mutation, or airgap
    behavior is introduced in Slice 1.

    ``plan_id`` is FK ``ON DELETE RESTRICT`` so a plan whose
    executions still reference it cannot disappear out from under
    the audit trail. ``policy_snapshot`` /
    ``execution_config_snapshot`` capture moment-in-time inputs so
    later policy edits cannot change what an execution was built
    from. ``progress_summary`` is a JSONB rollup the route layer
    refreshes from the per-host rows.

    State vocabulary: ``pending`` / ``running`` / ``paused`` /
    ``succeeded`` / ``failed`` / ``canceled``. Slice 1 only writes
    ``pending`` (placeholder), ``running`` (start), ``paused``,
    ``canceled``; ``succeeded`` / ``failed`` are RESERVED for later
    slices.
    """

    __tablename__ = "patch_update_executions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    plan_id = Column(
        Integer,
        ForeignKey("patch_update_plans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state = Column(String(32), nullable=False)
    started_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    paused_at = Column(DateTime, nullable=True)
    canceled_at = Column(DateTime, nullable=True)
    max_parallel_per_wave = Column(Integer, nullable=False)
    failure_threshold_percent = Column(Integer, nullable=True)
    pause_reason = Column(Text, nullable=True)
    cancel_reason = Column(Text, nullable=True)
    plan_state_snapshot = Column(String(32), nullable=False)
    policy_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    execution_config_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    progress_summary = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    plan = relationship("PatchUpdatePlan", foreign_keys=[plan_id])
    starter = relationship("User", foreign_keys=[started_by])
    hosts = relationship(
        "PatchUpdateExecutionHost",
        back_populates="execution",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'running', 'paused', 'succeeded', "
            "'failed', 'canceled')",
            name="patch_update_executions_state_vocab",
        ),
        CheckConstraint(
            "max_parallel_per_wave >= 1",
            name="patch_update_executions_parallel_min",
        ),
        CheckConstraint(
            "failure_threshold_percent IS NULL OR "
            "(failure_threshold_percent >= 0 AND failure_threshold_percent <= 100)",
            name="patch_update_executions_threshold_range",
        ),
        Index(
            "ix_patch_update_executions_plan_state",
            "plan_id",
            "state",
        ),
        Index(
            "uq_patch_update_executions_plan_active",
            "plan_id",
            unique=True,
            postgresql_where=sa_text("state IN ('pending', 'running', 'paused')"),
        ),
    )


class PatchUpdateExecutionHost(Base):  # pylint: disable=too-few-public-methods
    """Per-host execution row materialized from a PatchUpdatePlanHost (PRA-171 slice 1).

    Slice 1 initializes one row per plan host:

    * ``planned`` plan hosts -> ``pending``
    * ``blocked`` / targetless plan hosts -> ``skipped`` with
      structured ``skip_reasons`` copied from the plan host
    * ``planned`` plan hosts whose Slice 2 selection produced zero
      selected packages -> ``skipped`` with the
      ``no_selected_packages`` reason

    ``plan_host_id`` is FK ``ON DELETE RESTRICT`` so the source
    plan-host artifact cannot vanish out from under an execution
    row. ``system_id_snapshot`` / ``system_hostname_snapshot`` /
    ``selected_package_count`` are snapshotted so the execution row
    stays auditable even after later host removal or selection
    refresh on the parent plan.

    State vocabulary: ``pending`` / ``running`` / ``succeeded`` /
    ``failed`` / ``skipped`` / ``paused`` / ``canceled``. Slice 1
    only writes ``pending``, ``skipped``, and ``canceled``; the
    other transitions belong to later slices that wire real
    package-manager dispatch.
    """

    __tablename__ = "patch_update_execution_hosts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_id = Column(
        Integer,
        ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_host_id = Column(
        Integer,
        ForeignKey("patch_update_plan_hosts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    system_id_snapshot = Column(Integer, nullable=True)
    system_hostname_snapshot = Column(String(255), nullable=True)
    wave_index = Column(Integer, nullable=False)
    state = Column(String(32), nullable=False)
    selected_package_count = Column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    skip_reasons = Column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    error_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    execution = relationship("PatchUpdateExecution", back_populates="hosts")
    plan_host = relationship("PatchUpdatePlanHost", foreign_keys=[plan_host_id])
    packages = relationship(
        "PatchUpdateExecutionHostPackage",
        back_populates="execution_host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            "plan_host_id",
            name="uq_patch_update_execution_hosts_target",
        ),
        CheckConstraint(
            "state IN ('pending', 'running', 'succeeded', 'failed', "
            "'skipped', 'paused', 'canceled')",
            name="patch_update_execution_hosts_state_vocab",
        ),
        CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_hosts_wave_index_nonneg",
        ),
        CheckConstraint(
            "selected_package_count >= 0",
            name="patch_update_execution_hosts_selected_count_nonneg",
        ),
        Index(
            "ix_patch_update_execution_hosts_execution_wave",
            "execution_id",
            "wave_index",
        ),
        Index(
            "ix_patch_update_execution_hosts_execution_state",
            "execution_id",
            "state",
        ),
        Index(
            "ix_patch_update_execution_hosts_plan_host",
            "plan_host_id",
        ),
    )


class PatchUpdateExecutionHostPackage(Base):  # pylint: disable=too-few-public-methods
    """Per-package execution result row (PRA-171 slice 2).

    One row per package the dispatcher attempted on a single
    execution-host. Captures the intent (requested version snapshot,
    package family snapshot from preflight) and the outcome
    (succeeded / failed / skipped / unknown) along with the
    structured failure code and any per-package metadata the
    dispatcher recorded.

    ``execution_host_id`` is FK ``ON DELETE CASCADE`` so per-package
    rows go away when their parent execution-host is archived. The
    package row is keyed by ``package_name`` (no FK to
    ``patch_update_plan_selected_packages`` because the source row
    may be deleted between dispatch time and a much later audit
    query — the snapshot columns preserve audit-grade intent).

    Slice 2 fills ``installed_version_after`` only when the
    dispatcher's per-package observation is reliable; otherwise it
    stays NULL and a future verification slice may populate it.
    """

    __tablename__ = "patch_update_execution_host_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_host_id = Column(
        Integer,
        ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_name = Column(String(255), nullable=False)
    requested_version_snapshot = Column(String(255), nullable=True)
    installed_version_before = Column(String(255), nullable=True)
    installed_version_after = Column(String(255), nullable=True)
    package_manager_family_snapshot = Column(String(16), nullable=False)
    outcome = Column(String(32), nullable=False)
    error_code = Column(String(64), nullable=True)
    details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    execution_host = relationship("PatchUpdateExecutionHost", back_populates="packages")

    __table_args__ = (
        UniqueConstraint(
            "execution_host_id",
            "package_name",
            name="uq_patch_update_execution_host_packages_target",
        ),
        CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'skipped', 'unknown')",
            name="patch_update_execution_host_packages_outcome_vocab",
        ),
        CheckConstraint(
            "package_manager_family_snapshot IN ('apt', 'dnf', 'unknown')",
            name="patch_update_execution_host_packages_family_vocab",
        ),
        Index(
            "ix_patch_update_execution_host_packages_host_outcome",
            "execution_host_id",
            "outcome",
        ),
        Index(
            "ix_patch_update_execution_host_packages_host_package",
            "execution_host_id",
            "package_name",
        ),
    )


class PatchUpdateExecutionReboot(Base):  # pylint: disable=too-few-public-methods
    """Reboot-queue row for an execution host (PRA-172 slice 1).

    One row per ``PatchUpdateExecutionHost``, initialized after the
    parent execution reaches a terminal state. The row captures the
    moment-in-time reboot-policy decision plus the source facts the
    decision drew on, so the audit trail survives later policy or
    host edits. Slice 1 writes only ``not_required`` / ``pending`` /
    ``skipped``; the remaining states (``scheduled``, ``rebooting``,
    ``verifying``, ``healthy``, ``failed``) are reserved for the
    later PRA-172 slices that wire actual reboot execution and
    health verification.

    ``execution_host_id`` is FK ``ON DELETE CASCADE`` so reboot
    rows go away when their parent execution-host is archived. The
    ``plan_id_snapshot`` / ``system_id_snapshot`` /
    ``system_hostname_snapshot`` / ``reboot_policy_snapshot`` /
    ``reboot_window_id_snapshot`` columns capture audit-grade
    intent so historical lookups stay readable after later edits.

    ``decision_code`` is a short machine-readable reason
    (``host_fact_reboot_required`` / ``policy_always`` /
    ``fact_not_required`` / ``policy_never`` /
    ``host_did_not_succeed`` / ``policy_invalid`` /
    ``policy_missing``) and ``decision_details`` carries any
    structured context the operator UI needs to render the "why".
    """

    __tablename__ = "patch_update_execution_reboots"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_id = Column(
        Integer,
        ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    execution_host_id = Column(
        Integer,
        ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_id_snapshot = Column(Integer, nullable=False)
    system_id_snapshot = Column(Integer, nullable=True)
    system_hostname_snapshot = Column(String(255), nullable=True)
    wave_index = Column(Integer, nullable=False)
    state = Column(String(32), nullable=False)
    reboot_policy_snapshot = Column(String(32), nullable=False)
    reboot_window_id_snapshot = Column(Integer, nullable=True)
    reboot_required_fact = Column(Boolean, nullable=True)
    decision_code = Column(String(64), nullable=False)
    decision_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    scheduled_for_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    # Slice 3 dispatch result columns. Nullable because Slice 1+2
    # rows never write them; populated when ``scheduled`` is
    # transitioned to ``rebooting`` (or directly to ``failed`` on
    # dispatch failure).
    transport_kind = Column(String(16), nullable=True)
    command_snapshot = Column(Text, nullable=True)
    exit_signal_kind = Column(String(32), nullable=True)
    dispatch_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    # Slice 4 verification result columns. Nullable because Slice
    # 1-3 rows never write them; populated when ``rebooting`` is
    # transitioned to ``healthy`` / ``failed`` by the Slice 4
    # verifier. ``verification_details`` is JSONB context the
    # operator UI renders: observed boot_id / uptime evidence,
    # probe attempts, failure reason code.
    verified_at = Column(DateTime, nullable=True)
    verification_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    execution = relationship("PatchUpdateExecution", foreign_keys=[execution_id])
    execution_host = relationship(
        "PatchUpdateExecutionHost", foreign_keys=[execution_host_id]
    )

    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            "execution_host_id",
            name="uq_patch_update_execution_reboots_target",
        ),
        CheckConstraint(
            "state IN ('not_required', 'pending', 'scheduled', 'rebooting', "
            "'verifying', 'healthy', 'failed', 'skipped')",
            name="patch_update_execution_reboots_state_vocab",
        ),
        CheckConstraint(
            "reboot_policy_snapshot IN ('never', 'if_required', 'always', "
            "'unknown')",
            name="patch_update_execution_reboots_policy_vocab",
        ),
        CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_reboots_wave_index_nonneg",
        ),
        CheckConstraint(
            "exit_signal_kind IS NULL OR exit_signal_kind IN ("
            "'exit_zero', 'connection_lost_clean', 'non_zero', "
            "'timeout', 'transport_error', 'transport_unavailable')",
            name="patch_update_execution_reboots_exit_signal_kind_vocab",
        ),
        Index(
            "ix_patch_update_execution_reboots_execution_state",
            "execution_id",
            "state",
        ),
        Index(
            "ix_patch_update_execution_reboots_execution_wave",
            "execution_id",
            "wave_index",
        ),
        Index(
            "ix_patch_update_execution_reboots_plan",
            "plan_id_snapshot",
        ),
    )


class PatchUpdateExecutionRollback(Base):  # pylint: disable=too-few-public-methods
    """Per-execution rollback feasibility "plan" row (PRA-173 slice 1).

    One row per :class:`PatchUpdateExecution`. Captures the moment-in-
    time feasibility decision plus the plan/execution snapshot the
    decision drew on, so the audit trail survives later policy /
    content / host edits.

    ``state`` is ``evaluated`` when the execution was in a terminal
    state and a per-host/per-package rollup was produced;
    ``refused`` when the plan-level evaluation gate failed (e.g.
    ``execution_not_terminal``). Slice 1 never silently omits an
    execution — refusal states are explicit so the read API can
    render the "why we cannot evaluate this execution" message
    without inventing a state on the route layer.

    ``feasibility_summary`` is a JSONB rollup the service computes on
    every re-evaluate: host-state counts, package-state counts, and a
    by-refusal_reason breakdown so the operator UI can render
    "N packages refused for content_profile_missing" without
    re-querying the per-package rows.
    """

    __tablename__ = "patch_update_execution_rollbacks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_id = Column(
        Integer,
        ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_id_snapshot = Column(Integer, nullable=False)
    execution_state_snapshot = Column(String(32), nullable=False)
    state = Column(String(32), nullable=False)
    refusal_reason = Column(String(64), nullable=True)
    refusal_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    feasibility_summary = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    evaluated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    execution = relationship("PatchUpdateExecution", foreign_keys=[execution_id])
    hosts = relationship(
        "PatchUpdateExecutionRollbackHost",
        back_populates="rollback",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            name="uq_patch_update_execution_rollbacks_execution",
        ),
        CheckConstraint(
            "state IN ('evaluated', 'refused')",
            name="patch_update_execution_rollbacks_state_vocab",
        ),
        Index(
            "ix_patch_update_execution_rollbacks_plan",
            "plan_id_snapshot",
        ),
    )


class PatchUpdateExecutionRollbackHost(Base):  # pylint: disable=too-few-public-methods
    """Per-execution-host rollback feasibility row (PRA-173 slice 1).

    One row per :class:`PatchUpdateExecutionHost`. Mirrors the plan-
    host artifact: every in-scope execution host gets an explicit
    rollback row, including skipped/failed/unsupported hosts with
    structured refusal details.

    ``state`` is derived from the per-package rollup:

    * ``feasible`` — every package row is feasible.
    * ``partial_feasible`` — at least one package row is feasible
      and at least one is not.
    * ``infeasible`` — no package row is feasible, OR the host
      state is not ``succeeded`` (in which case
      ``refusal_reason='host_not_succeeded'``).

    ``content_profile_snapshot`` captures the host's effective
    content-profile context at evaluation time (snapshotted from the
    plan host's ``content_profile_*`` columns), so a later edit to
    the host's profile binding does not silently rewrite historical
    intent.

    ``package_summary`` is the per-host rollup: ``feasible`` /
    ``infeasible`` counts plus a by-reason breakdown so the operator
    UI can render the host's "why" without a child-row query.
    """

    __tablename__ = "patch_update_execution_rollback_hosts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
        nullable=False,
    )
    execution_host_id = Column(
        Integer,
        ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_host_id_snapshot = Column(Integer, nullable=False)
    system_id_snapshot = Column(Integer, nullable=True)
    system_hostname_snapshot = Column(String(255), nullable=True)
    wave_index = Column(Integer, nullable=False)
    execution_host_state_snapshot = Column(String(32), nullable=False)
    state = Column(String(32), nullable=False)
    refusal_reason = Column(String(64), nullable=True)
    refusal_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    content_profile_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    package_summary = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    evaluated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    rollback = relationship("PatchUpdateExecutionRollback", back_populates="hosts")
    execution_host = relationship(
        "PatchUpdateExecutionHost", foreign_keys=[execution_host_id]
    )
    packages = relationship(
        "PatchUpdateExecutionRollbackPackage",
        back_populates="rollback_host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "rollback_id",
            "execution_host_id",
            name="uq_patch_update_execution_rollback_hosts_target",
        ),
        CheckConstraint(
            "state IN ('feasible', 'partial_feasible', 'infeasible')",
            name="patch_update_execution_rollback_hosts_state_vocab",
        ),
        CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_rollback_hosts_wave_index_nonneg",
        ),
        Index(
            "ix_patch_update_execution_rollback_hosts_rollback_state",
            "rollback_id",
            "state",
        ),
        Index(
            "ix_patch_update_execution_rollback_hosts_execution_host",
            "execution_host_id",
        ),
    )


class PatchUpdateExecutionRollbackPackage(
    Base
):  # pylint: disable=too-few-public-methods
    """Per-package rollback feasibility row (PRA-173 slice 1).

    One row per ``PatchUpdateExecutionHostPackage`` candidate. Captures
    the old version (``installed_version_before_snapshot``), the post-
    update target (``installed_version_after_snapshot`` /
    ``requested_version_snapshot``), the package-manager family, the
    execution outcome, and the per-package feasibility verdict.

    ``target_rollback_version`` is the resolved value the rollback
    *would* target if executed: equal to
    ``installed_version_before_snapshot`` for feasible rows, null
    otherwise. The rollback execution layer (later slice) reads this
    column rather than re-deriving from the snapshot columns so the
    decision is durable.

    ``execution_host_package_id`` is FK ``ON DELETE SET NULL`` so a
    later archive of the source PRA-171 row does not cascade-delete
    the audit trail. The snapshot columns preserve audit-grade intent
    even after the FK target disappears.

    ``content_evidence`` records which channel/mirror/run was
    inspected and what matched (``available`` vs which negative
    results), so the audit trail proves *why* a row is feasible (or
    not) without a re-query.
    """

    __tablename__ = "patch_update_execution_rollback_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_host_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollback_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    execution_host_package_id = Column(
        Integer,
        ForeignKey("patch_update_execution_host_packages.id", ondelete="SET NULL"),
        nullable=True,
    )
    package_name = Column(String(255), nullable=False)
    package_manager_family_snapshot = Column(String(16), nullable=False)
    installed_version_before_snapshot = Column(String(255), nullable=True)
    installed_version_after_snapshot = Column(String(255), nullable=True)
    requested_version_snapshot = Column(String(255), nullable=True)
    target_rollback_version = Column(String(255), nullable=True)
    package_outcome_snapshot = Column(String(32), nullable=False)
    state = Column(String(32), nullable=False)
    refusal_reason = Column(String(64), nullable=True)
    refusal_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    content_evidence = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    # PRA-173 slice 2: per-feasible-package rollback command plan.
    # Nullable: only set on feasible rows (infeasible rows have no
    # dispatchable command). JSONB shape carries family-specific
    # primary command argv + command_string plus
    # held-package / versionlock handling metadata that Slice 3
    # dispatch reads at execution time. Re-evaluating refreshes
    # the value; the moment-in-time *approved* plan is frozen
    # separately on the rollback approval link row so re-evaluate
    # cannot silently rewrite what operators voted on.
    command_plan = Column(JSONB, nullable=True)
    evaluated_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    rollback_host = relationship(
        "PatchUpdateExecutionRollbackHost", back_populates="packages"
    )
    execution_host_package = relationship(
        "PatchUpdateExecutionHostPackage",
        foreign_keys=[execution_host_package_id],
    )

    __table_args__ = (
        UniqueConstraint(
            "rollback_host_id",
            "package_name",
            name="uq_patch_update_execution_rollback_packages_target",
        ),
        CheckConstraint(
            "state IN ('feasible', 'infeasible')",
            name="patch_update_execution_rollback_packages_state_vocab",
        ),
        CheckConstraint(
            "package_manager_family_snapshot IN ('apt', 'dnf', 'unknown')",
            name="patch_update_execution_rollback_packages_family_vocab",
        ),
        Index(
            "ix_patch_update_execution_rollback_packages_host_state",
            "rollback_host_id",
            "state",
        ),
        Index(
            "ix_patch_update_execution_rollback_packages_exec_pkg",
            "execution_host_package_id",
        ),
    )


class PatchUpdateExecutionRollbackApproval(
    Base
):  # pylint: disable=too-few-public-methods
    """Rollback ↔ patch-approval link (PRA-173 slice 2).

    Mirrors :class:`PatchUpdatePlanApproval` shape: joins a
    :class:`PatchUpdateExecutionRollback` header row to a PRA-161
    :class:`PatchApproval` row (``subject_kind='rollback'`` enforced
    at the service layer, not at the DB).

    ``frozen_plan_snapshot`` captures the moment-in-time command-
    plan snapshot operators are voting on: ``{"hosts": [...]}`` with
    per-host, per-package frozen ``command_plan`` blobs. Slice 3
    dispatch reads the frozen snapshot, not the live
    ``command_plan`` column on the package row, so a later
    re-evaluate that refreshes per-package plans cannot silently
    rewrite the bytes operators approved.

    ``rollback_id`` is FK CASCADE so the link disappears when the
    rollback header is deleted (which only happens when the parent
    execution is deleted, which is itself CASCADE-on-plan-only via
    ``RESTRICT``). ``approval_id`` is FK RESTRICT so an in-flight
    approval cannot vanish out from under the link.
    """

    __tablename__ = "patch_update_execution_rollback_approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
        nullable=False,
    )
    approval_id = Column(
        Integer,
        ForeignKey("patch_approvals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    requested_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    requested_at = Column(DateTime, nullable=False)
    frozen_plan_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    rollback = relationship("PatchUpdateExecutionRollback", foreign_keys=[rollback_id])
    approval = relationship("PatchApproval", foreign_keys=[approval_id])
    requester = relationship("User", foreign_keys=[requested_by])

    __table_args__ = (
        UniqueConstraint(
            "rollback_id",
            "approval_id",
            name="uq_patch_update_execution_rollback_approvals_target",
        ),
        Index(
            "ix_patch_update_execution_rollback_approvals_rollback",
            "rollback_id",
        ),
        Index(
            "ix_patch_update_execution_rollback_approvals_approval",
            "approval_id",
        ),
    )


class PatchRollbackDispatchRun(Base):  # pylint: disable=too-few-public-methods
    """Per-rollback dispatch attempt header (PRA-173 slice 3).

    One row per explicit operator-triggered rollback dispatch. FK
    to the rollback feasibility header and to the *specific* PRA-173
    Slice 2 approval link operators voted on. The approval link's
    ``frozen_plan_snapshot`` is the dispatch authority — Slice 3
    consumes that JSONB shape, NOT the live ``command_plan`` columns
    on the feasibility package rows.

    ``rollback_approval_link_id`` is FK ``ON DELETE RESTRICT`` so an
    in-flight dispatch cannot have its source-of-truth vanish out
    from under it. ``rollback_id`` is FK ``ON DELETE CASCADE`` for
    the same reason as the rollback header itself — the parent
    execution being deleted is the only way a rollback header
    disappears, and that already cascades through every layer.

    State vocabulary: ``pending`` / ``running`` / ``paused`` /
    ``succeeded`` / ``failed`` / ``canceled``. Slice 3 writes
    ``running`` at start, ``succeeded`` / ``failed`` on completion,
    ``canceled`` on explicit cancel. ``paused`` / ``pending`` are
    reserved for later slices that may add scheduling.

    The partial-unique index ``uq_…_rollback_active`` enforces
    *one live dispatch per rollback*; operators get a clear 422
    if they try to start a second dispatch while a previous one
    is still in flight.
    """

    __tablename__ = "patch_rollback_dispatch_runs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
        nullable=False,
    )
    rollback_approval_link_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollback_approvals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state = Column(String(32), nullable=False)
    started_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    paused_at = Column(DateTime, nullable=True)
    canceled_at = Column(DateTime, nullable=True)
    max_parallel = Column(Integer, nullable=False)
    pause_reason = Column(Text, nullable=True)
    cancel_reason = Column(Text, nullable=True)
    progress_summary = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    rollback = relationship("PatchUpdateExecutionRollback", foreign_keys=[rollback_id])
    approval_link = relationship(
        "PatchUpdateExecutionRollbackApproval",
        foreign_keys=[rollback_approval_link_id],
    )
    starter = relationship("User", foreign_keys=[started_by])
    hosts = relationship(
        "PatchRollbackDispatchHost",
        back_populates="dispatch_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'running', 'paused', 'succeeded', "
            "'failed', 'canceled')",
            name="patch_rollback_dispatch_runs_state_vocab",
        ),
        CheckConstraint(
            "max_parallel >= 1",
            name="patch_rollback_dispatch_runs_max_parallel_min",
        ),
        Index(
            "ix_patch_rollback_dispatch_runs_rollback_state",
            "rollback_id",
            "state",
        ),
        Index(
            "ix_patch_rollback_dispatch_runs_approval_link",
            "rollback_approval_link_id",
        ),
        Index(
            "uq_patch_rollback_dispatch_runs_rollback_active",
            "rollback_id",
            unique=True,
            postgresql_where=sa_text("state IN ('pending', 'running', 'paused')"),
        ),
    )


class PatchRollbackDispatchHost(Base):  # pylint: disable=too-few-public-methods
    """Per-host rollback dispatch row (PRA-173 slice 3).

    One row per host that the frozen plan snapshot covers. Mirrors
    the PRA-171 :class:`PatchUpdateExecutionHost` shape so the
    existing live-progress UI component renders rollback host
    status without a new component family.

    ``rollback_host_id`` is FK ``ON DELETE CASCADE`` — if the
    source rollback host row disappears, the dispatch row goes
    with it. State vocabulary mirrors PRA-171:
    ``pending`` / ``running`` / ``succeeded`` / ``failed`` /
    ``skipped`` / ``canceled``.
    """

    __tablename__ = "patch_rollback_dispatch_hosts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_dispatch_run_id = Column(
        Integer,
        ForeignKey("patch_rollback_dispatch_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    rollback_host_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollback_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    system_id_snapshot = Column(Integer, nullable=True)
    system_hostname_snapshot = Column(String(255), nullable=True)
    state = Column(String(32), nullable=False)
    error_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    dispatch_run = relationship("PatchRollbackDispatchRun", back_populates="hosts")
    rollback_host = relationship(
        "PatchUpdateExecutionRollbackHost", foreign_keys=[rollback_host_id]
    )
    packages = relationship(
        "PatchRollbackDispatchHostPackage",
        back_populates="dispatch_host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "rollback_dispatch_run_id",
            "rollback_host_id",
            name="uq_patch_rollback_dispatch_hosts_target",
        ),
        CheckConstraint(
            "state IN ('pending', 'running', 'succeeded', 'failed', "
            "'skipped', 'canceled')",
            name="patch_rollback_dispatch_hosts_state_vocab",
        ),
        Index(
            "ix_patch_rollback_dispatch_hosts_run_state",
            "rollback_dispatch_run_id",
            "state",
        ),
        Index(
            "ix_patch_rollback_dispatch_hosts_rollback_host",
            "rollback_host_id",
        ),
    )


class PatchRollbackDispatchHostPackage(Base):  # pylint: disable=too-few-public-methods
    """Per-package rollback dispatch outcome row (PRA-173 slice 3).

    One row per package per dispatch host. Mirrors the PRA-171
    :class:`PatchUpdateExecutionHostPackage` shape with two extra
    columns for the rollback-specific contract:

    * ``target_rollback_version_snapshot`` — the version the
      frozen plan said dispatch would target. Recorded so an
      operator-facing audit can confirm "we asked for V, we got V".
    * ``installed_version_after`` — the version observed after the
      rollback command ran. Slice 3 records ``None`` here when the
      dispatcher cannot reliably read it; Slice 4 (re-scan /
      verification) will populate it from a follow-up fact refresh.

    Outcome vocabulary: ``pending`` (default at materialization) /
    ``succeeded`` / ``failed`` / ``skipped`` / ``unknown``. Slice 3
    writes the non-``pending`` values; ``pending`` exists so a
    materialized row that never reaches dispatch (e.g. host was
    canceled before its turn) is still self-describing.

    ``rollback_package_id`` is FK ``ON DELETE SET NULL`` so a later
    archive of the source feasibility row does not cascade-delete
    the dispatch audit trail; the snapshot columns preserve intent.
    """

    __tablename__ = "patch_rollback_dispatch_host_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rollback_dispatch_host_id = Column(
        Integer,
        ForeignKey("patch_rollback_dispatch_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    rollback_package_id = Column(
        Integer,
        ForeignKey("patch_update_execution_rollback_packages.id", ondelete="SET NULL"),
        nullable=True,
    )
    package_name = Column(String(255), nullable=False)
    package_manager_family_snapshot = Column(String(16), nullable=False)
    target_rollback_version_snapshot = Column(String(255), nullable=True)
    installed_version_before = Column(String(255), nullable=True)
    installed_version_after = Column(String(255), nullable=True)
    outcome = Column(String(32), nullable=False)
    error_code = Column(String(64), nullable=True)
    details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    # PRA-173 slice 4a: explicit "this row has been
    # verified" sentinel. NULL = not yet verified; non-null = the
    # verifier observed the host's state at this moment, and the
    # ``installed_version_after`` value (including ``None``) is
    # authoritative. Slice 4's ``installed_version_after IS NULL``
    # collided with "verified, not installed"; this column
    # disambiguates so idempotency / completion work for null
    # observations.
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    dispatch_host = relationship("PatchRollbackDispatchHost", back_populates="packages")
    rollback_package = relationship(
        "PatchUpdateExecutionRollbackPackage",
        foreign_keys=[rollback_package_id],
    )

    __table_args__ = (
        UniqueConstraint(
            "rollback_dispatch_host_id",
            "package_name",
            name="uq_patch_rollback_dispatch_host_packages_target",
        ),
        CheckConstraint(
            "outcome IN ('pending', 'succeeded', 'failed', 'skipped', 'unknown')",
            name="patch_rollback_dispatch_host_packages_outcome_vocab",
        ),
        CheckConstraint(
            "package_manager_family_snapshot IN ('apt', 'dnf', 'unknown')",
            name="patch_rollback_dispatch_host_packages_family_vocab",
        ),
        Index(
            "ix_patch_rollback_dispatch_host_packages_host_outcome",
            "rollback_dispatch_host_id",
            "outcome",
        ),
        Index(
            "ix_patch_rollback_dispatch_host_packages_rb_pkg",
            "rollback_package_id",
        ),
    )


class CARotation(Base):  # pylint: disable=too-few-public-methods
    """Audit trail of SSH CA rotation + cert revocation events (PRA-128)."""

    __tablename__ = "ca_rotations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_type = Column(String(20), nullable=False)  # rotate | revoke
    ca_identifier = Column(String(100), nullable=True)
    ca_public_key = Column(Text, nullable=True)
    performed_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    performed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user = relationship("User")


class CommandTemplate(Base):  # pylint: disable=too-few-public-methods
    """CommandTemplate model for parameterized command templates."""

    __tablename__ = "command_templates"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    template = Column(
        String(1000), nullable=False
    )  # e.g., "apt-get install {package_name}"
    category = Column(String(100), nullable=False)
    parameters = Column(Text, nullable=True)  # JSON string of parameter definitions
    is_active = Column(Boolean, default=True, nullable=False)
    risk_level = Column(String(50), nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Relationships
    template_distros = relationship(
        "CommandTemplateDistro", back_populates="template", cascade="all, delete-orphan"
    )


class Notification(Base):  # pylint: disable=too-few-public-methods
    """Notification model for in-app job notifications."""

    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    type = Column(
        String(50), nullable=False
    )  # job_completed, job_failed, job_cancelled
    title = Column(String(200), nullable=False)
    message = Column(Text)
    severity = Column(
        String(20), nullable=False, default="info"
    )  # info, warning, error
    is_read = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=True)  # null = all users
    related_job_id = Column(Integer, ForeignKey("jobs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    job = relationship("Job")


class NotificationPreference(Base):  # pylint: disable=too-few-public-methods
    """Per-user notification preferences (PRA-100).

    Stores which event types a user has disabled.  All types are enabled
    by default; ``disabled_types`` is a JSON array of type strings the
    user has opted out of.
    """

    __tablename__ = "notification_preferences"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False, unique=True)
    disabled_types = Column(Text, nullable=False, server_default="[]")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")


class AlertConfig(Base):  # pylint: disable=too-few-public-methods
    """Alert configuration for external notifications (PRA-41)."""

    __tablename__ = "alert_configs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    alert_type = Column(String(50), nullable=False)  # slack, webhook
    destination = Column(
        Text, nullable=False
    )  # Slack webhook URL or generic webhook URL
    events = Column(Text, nullable=False)  # JSON array of event types
    enabled = Column(Boolean, default=True, nullable=False)
    secret = Column(String(255), nullable=True)  # HMAC-SHA256 key (PRA-125)
    # PRA-126: scope delivery to a smart group (null = fleet-wide)
    scope_smart_group_id = Column(
        Integer, ForeignKey("smart_groups.id", ondelete="SET NULL"), nullable=True
    )
    created_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    creator = relationship("User")
    history = relationship(
        "AlertHistory", back_populates="alert_config", cascade="all, delete-orphan"
    )


class AlertHistory(Base):  # pylint: disable=too-few-public-methods
    """History of sent alerts (PRA-41)."""

    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_config_id = Column(
        Integer,
        ForeignKey("alert_configs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(50), nullable=False)
    message = Column(Text, nullable=True)
    sent_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # pending, sent, failed, dead_letter (PRA-125)
    status = Column(String(20), nullable=False)
    error_message = Column(Text, nullable=True)
    response_code = Column(Integer, nullable=True)
    # PRA-125 retry queue fields
    payload = Column(Text, nullable=True)  # serialized request body
    attempt_count = Column(Integer, nullable=False, default=1, server_default="1")
    next_retry_at = Column(DateTime, nullable=True, index=True)
    last_attempted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    alert_config = relationship("AlertConfig", back_populates="history")


class FleetOperation(Base):  # pylint: disable=too-few-public-methods
    """FleetOperation model: audit trail for bulk fleet actions (PRA-115)."""

    __tablename__ = "fleet_operations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    operation_type = Column(String(100), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    target_count = Column(Integer, nullable=False, default=0)
    success_count = Column(Integer, nullable=False, default=0)
    failure_count = Column(Integer, nullable=False, default=0)
    parameters = Column(Text, nullable=True)  # JSON-encoded input snapshot
    status = Column(
        String(50), nullable=False, default="running"
    )  # running, completed, failed, partial
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    results = relationship(
        "FleetOperationResult",
        back_populates="operation",
        cascade="all, delete-orphan",
    )


class FleetOperationResult(Base):  # pylint: disable=too-few-public-methods
    """Per-system result within a FleetOperation (PRA-115)."""

    __tablename__ = "fleet_operation_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    fleet_operation_id = Column(
        Integer,
        ForeignKey("fleet_operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer, ForeignKey("systems.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String(50), nullable=False)  # success, failure, skipped
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    operation = relationship("FleetOperation", back_populates="results")
    system = relationship("System")


class CommandTemplateDistro(Base):  # pylint: disable=too-few-public-methods
    """CommandTemplateDistro model for distribution-specific command templates."""

    __tablename__ = "command_template_distros"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    template_id = Column(Integer, ForeignKey("command_templates.id"), nullable=False)
    distro_id = Column(Integer, ForeignKey("distros.id"), nullable=False)
    distro_version_pattern = Column(String(100), nullable=True)
    template_override = Column(String(1000), nullable=True)
    is_supported = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    template = relationship("CommandTemplate", back_populates="template_distros")
    distro = relationship("Distro")


class GlobalConnectionSettings(Base):  # pylint: disable=too-few-public-methods
    """Singleton table for global SSH connection tunables (PRA-62)."""

    __tablename__ = "global_connection_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_timeout = Column(
        Integer, nullable=False, default=10, server_default="10"
    )
    max_pool_size = Column(Integer, nullable=False, default=50, server_default="50")
    pool_cleanup_interval = Column(
        Integer, nullable=False, default=300, server_default="300"
    )
    max_idle_time = Column(Integer, nullable=False, default=600, server_default="600")
    unreachable_threshold = Column(
        Integer, nullable=False, default=2, server_default="2"
    )
    default_ssh_port = Column(Integer, nullable=False, default=22, server_default="22")
    # PRA-313: per-host transport circuit-breaker tunables. After
    # ``transport_failure_threshold`` consecutive banner/connect/socket failures a
    # host enters a ``transport_cooldown_seconds`` cooldown during which normal ops
    # fast-fail without opening a socket. Kept separate from
    # ``unreachable_threshold`` (which drives fleet status) so a fast auth failure
    # never trips the slowness breaker.
    transport_failure_threshold = Column(
        Integer, nullable=False, default=3, server_default="3"
    )
    transport_cooldown_seconds = Column(
        Integer, nullable=False, default=60, server_default="60"
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SSHIdentitySettings(Base):  # pylint: disable=too-few-public-methods
    """Singleton table for zero-trust SSH identity (Vault CA) settings (PRA-44)."""

    __tablename__ = "ssh_identity_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_cert_ttl_seconds = Column(
        Integer, nullable=False, default=300, server_default="300"
    )
    default_principal = Column(String(100), nullable=True)
    ca_identifier = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SavedView(Base):  # pylint: disable=too-few-public-methods
    """Saved filter views for system lists (PRA-114)."""

    __tablename__ = "saved_views"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    filters = Column(Text, nullable=False)  # JSON filter configuration
    is_default = Column(Boolean, default=False, nullable=False)
    is_shared = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owner = relationship("User")


class MaintenanceWindow(Base):  # pylint: disable=too-few-public-methods
    """Maintenance window definitions for restricting job execution (PRA-79)."""

    __tablename__ = "maintenance_windows"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)  # system, group, all
    target_id = Column(Integer, nullable=True)  # system_id or group_id (null if all)
    schedule = Column(Text, nullable=False)  # JSON schedule definition
    enabled = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    creator = relationship("User")


class SmartGroup(Base):  # pylint: disable=too-few-public-methods
    """Rule-based dynamic system group (PRA-126).

    Membership is computed from ``rule_json`` and materialised into
    ``smart_group_memberships`` on create/update of the group or any of
    its inputs (systems, tags, static groups).
    """

    __tablename__ = "smart_groups"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    rule_json = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    created_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    creator = relationship("User")
    memberships = relationship(
        "SmartGroupMembership",
        back_populates="smart_group",
        cascade="all, delete-orphan",
    )


class SmartGroupMembership(Base):  # pylint: disable=too-few-public-methods
    """Cached membership rows for SmartGroup (PRA-126)."""

    __tablename__ = "smart_group_memberships"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
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
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    smart_group = relationship("SmartGroup", back_populates="memberships")
    system = relationship("System")


class Baseline(Base):  # pylint: disable=too-few-public-methods
    """Configuration baseline (PRA-127).

    rules_json shape:
        {"packages": [{"name": str, "check": "required"|"forbidden"|"version_pin",
                       "version": str?}],
         "services": [{"name": str, "check": "running"|"stopped"|"enabled"|"disabled"}]}
    """

    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    scope_smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rules_json = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    schedule_interval_hours = Column(
        Integer, nullable=False, default=24, server_default="24"
    )
    last_run_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    creator = relationship("User")
    checks = relationship(
        "BaselineCheck", back_populates="baseline", cascade="all, delete-orphan"
    )


class BaselineCheck(Base):  # pylint: disable=too-few-public-methods
    """Result of evaluating a Baseline against a System (PRA-127)."""

    __tablename__ = "baseline_checks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    baseline_id = Column(
        Integer,
        ForeignKey("baselines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = Column(String(20), nullable=False)  # compliant, drifted, error
    drift_details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    baseline = relationship("Baseline", back_populates="checks")
    system = relationship("System")


class AppSettings(Base):  # pylint: disable=too-few-public-methods
    """Key-value store for application-wide settings (PRA-85)."""

    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    setting_key = Column(String(100), unique=True, nullable=False, index=True)
    setting_value = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BootstrapAdminState(Base):  # pylint: disable=too-few-public-methods
    """Records that this installation has completed first-run initialization.

    The fact is about the installation, not about an account: once the row exists,
    the bootstrap path never provisions an administrator again, whatever later
    happened to the account it created. That is what separates a deployment
    that was never initialized from one whose administrator was deliberately
    deleted, renamed, disabled, or stripped of the admin role. ADMIN_PASSWORD
    and ADMIN_USERNAME are first-run inputs, not recurring desired state.

    ``marker`` always holds ``bootstrap_admin``. Two constraints make the
    single-row invariant a database fact rather than a convention, and both are
    needed: the check pins the column to that one literal, and the unique
    constraint then admits only one row carrying it. Uniqueness alone would
    permit any number of rows under different marker strings, each of which the
    reader would fail to find, and a first boot would provision over the top of
    a record that already said this installation was initialized. Together they
    are also the backstop for two backends racing through their first boot.

    ``bootstrap_user_id`` nulls out when the account is deleted, so the marker
    outlives what it describes. ``bootstrap_username`` is kept as history for
    that case; it is never a lookup key. No password material is stored.
    """

    __tablename__ = "bootstrap_admin_state"
    __table_args__ = (
        CheckConstraint(
            "marker = 'bootstrap_admin'",
            name="ck_bootstrap_admin_state_marker",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    marker = Column(String(32), unique=True, nullable=False)
    state = Column(String(20), nullable=False)
    bootstrap_user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    bootstrap_username = Column(String(200), nullable=True)
    initialized_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ActivationToken(Base):  # pylint: disable=too-few-public-methods
    """Activation token for one-line agent enrollment (PRA-154).

    Tokens are opaque secrets stored as bcrypt hashes; the raw secret
    is returned to the operator exactly once at create time. Each
    token binds a placement scope (default_group_id, optional tags),
    has a TTL, a max-uses cap, and is revocable. Redemption state
    lives in ``activation_token_redemptions`` so reruns are stable.
    """

    __tablename__ = "activation_tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    token_hash = Column(String(255), nullable=False)
    token_prefix = Column(String(16), nullable=False, index=True)
    default_group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    target_system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    default_tag_ids = Column(JSONB, nullable=False, default=list)
    ttl_expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, nullable=False)
    uses_count = Column(Integer, nullable=False, default=0)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by_user_id = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    created_by_user_id = Column(
        Integer, ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    default_group = relationship("Group")
    target_system = relationship("System", foreign_keys=[target_system_id])
    created_by = relationship("User", foreign_keys=[created_by_user_id])
    revoked_by = relationship("User", foreign_keys=[revoked_by_user_id])
    redemptions = relationship(
        "ActivationTokenRedemption",
        back_populates="activation_token",
        cascade="all, delete-orphan",
    )


class ActivationTokenRedemption(Base):  # pylint: disable=too-few-public-methods
    """Durable redemption ledger for activation tokens (PRA-154).

    Keyed on ``(activation_token_id, host_fingerprint_hash)`` so the
    same host re-running bootstrap with the same token resolves to
    the same ``system_id`` instead of creating a duplicate. The
    ``host_fingerprint_hash`` is the sha256 of the host-supplied
    fingerprint; the raw value never lands in the DB.
    """

    __tablename__ = "activation_token_redemptions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    activation_token_id = Column(
        Integer,
        ForeignKey("activation_tokens.id", ondelete="CASCADE"),
        nullable=False,
    )
    host_fingerprint_hash = Column(String(64), nullable=False)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    first_redeemed_at = Column(DateTime, nullable=False)
    last_redeemed_at = Column(DateTime, nullable=False)
    redeem_count = Column(Integer, nullable=False, default=1)
    last_seen_hostname = Column(String(255), nullable=True)
    last_seen_ip = Column(INET, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    activation_token = relationship("ActivationToken", back_populates="redemptions")
    system = relationship("System")


class HostFacts(Base):  # pylint: disable=too-few-public-methods
    """Canonical fleet inventory facts for a system (PRA-155).

    One current row per ``system_id``; history is deferred. Schema is
    transport-neutral — agent, SSH, and manual import all funnel through
    ``FactsService.ingest`` and write the same shape. ``source_transport``
    distinguishes provenance, not behavior.
    """

    __tablename__ = "host_facts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    schema_version = Column(Integer, nullable=False)
    collected_at = Column(DateTime, nullable=False)
    source_transport = Column(String(16), nullable=False)
    cpu_model = Column(String(255), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    ram_total_bytes = Column(BigInteger, nullable=True)
    kernel_version = Column(String(255), nullable=True)
    # Stored as ``distro_id_facts`` to avoid colliding with the
    # ``systems.distro_id`` FK semantics — this is the host-reported
    # distro identifier (e.g. "ubuntu", "rhel"), not the Praxis distro
    # row id.
    distro_id_facts = Column(String(64), nullable=True)
    distro_release = Column(String(64), nullable=True)
    uptime_seconds = Column(BigInteger, nullable=True)
    reboot_required = Column(Boolean, nullable=True)
    package_manager = Column(String(32), nullable=True)
    package_manager_version = Column(String(64), nullable=True)
    virtualization = Column(String(32), nullable=True)
    cloud_provider = Column(String(32), nullable=True)
    cloud_instance_metadata = Column(JSONB, nullable=True)
    # PRA-359: read-only SSH-server-config + kernel-sysctl scalars backing the
    # CIS starter-pack SSH/kernel checks. Stored as strings (the effective
    # ``sshd -T`` / ``sysctl -n`` text) so compliance's ``str(value) ==
    # str(expected)`` comparison matches operator-defined expected values.
    # Nullable + additive: a host that can't report a value leaves it NULL
    # (missing/null fact state), never a fake pass/fail.
    ssh_permit_root_login = Column(String(64), nullable=True)
    ssh_password_authentication = Column(String(64), nullable=True)
    sysctl_kernel_randomize_va_space = Column(String(64), nullable=True)
    sysctl_net_ipv4_ip_forward = Column(String(64), nullable=True)
    sysctl_net_ipv4_conf_all_rp_filter = Column(String(64), nullable=True)
    disks = Column(JSONB, nullable=True)
    partial_errors = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    system = relationship("System")


class DistroLifecycle(Base):  # pylint: disable=too-few-public-methods
    """Reference data for distro release end-of-life dates (PRA-156).

    Keyed by ``(distro_id, release, support_kind)`` so multiple support
    windows can coexist for the same release (e.g. Ubuntu 22.04 has a
    standard EOL and an ESM EOL). Lookup is by the host-reported
    ``host_facts.distro_id_facts`` and ``host_facts.distro_release``
    strings — NOT by ``systems.distro_id``, which is registration-time
    and may be stale. Host facts are the fresh transport-neutral truth.

    The override behavior that consults non-standard ``support_kind``
    rows lands in PRA-156 #3e via ``distro_lifecycle_override``; in #3a
    only ``support_kind='standard'`` rows are consumed by
    ``LifecycleService.compute``.
    """

    __tablename__ = "distro_lifecycle"
    # Mirror the Alembic migration's constraints + index in the model
    # metadata so ``Base.metadata.create_all`` (used by the test
    # conftest) produces the same schema as production. The named
    # unique constraint is also referenced by
    # ``app.scripts.update_eol_data``'s ``ON CONFLICT DO UPDATE`` —
    # if the name diverges between this and the migration, the
    # operator-facing refresh path breaks.
    __table_args__ = (
        UniqueConstraint(
            "distro_id",
            "release",
            "support_kind",
            name="distro_lifecycle_unique_per_kind",
        ),
        CheckConstraint(
            "support_kind IN ('standard', 'esm', 'extended')",
            name="distro_lifecycle_support_kind_valid",
        ),
        Index(
            "ix_distro_lifecycle_distro_release",
            "distro_id",
            "release",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    distro_id = Column(String(64), nullable=False)
    release = Column(String(64), nullable=False)
    eol_date = Column(Date, nullable=False)
    # standard | esm | extended
    support_kind = Column(String(16), nullable=False)
    source = Column(String(255), nullable=False)
    as_of = Column(Date, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class LifecycleNotificationState(Base):  # pylint: disable=too-few-public-methods
    """Dedup state for the lifecycle notification emitter (PRA-156 #3e-c).

    Records that Praxis has already emitted a given lifecycle event for
    a given host at a given threshold + EOL date. The emitter consults
    this table before firing so each (system, threshold, EOL date)
    combination notifies exactly once.

    ``effective_eol_date`` lives in the dedup key so an override
    extension that moves a host's EOL date out (Ubuntu Pro, RHEL ELS)
    causes the dedup keys to change — the new EOL date triggers a
    fresh threshold sequence rather than being silently swallowed by
    state from the prior date.

    ``threshold_days`` semantics:
      * ``host_eol_approaching`` → ``threshold_days`` ∈ {7, 30, 90}.
      * ``host_eol_reached``     → ``threshold_days`` = 0 (the
        day-zero boundary; per the lock, reached fires at
        ``days_to_eol == 0`` only).

    Using 0 (not NULL) for the reached threshold keeps the UNIQUE
    constraint working without depending on Postgres NULLS NOT
    DISTINCT semantics (PG 15+) or a sentinel like -1.

    NOT a replacement for ``alert_history`` (PRA-41 / PRA-125):
    ``alert_history`` is external delivery history per
    ``alert_config``, populated by ``alert_service.send_alert``. This
    table is the upstream "did we emit?" gate — the emitter writes
    here AFTER it decides to send, regardless of how many configs
    matched or whether external delivery succeeded.
    """

    __tablename__ = "lifecycle_notification_state"
    __table_args__ = (
        UniqueConstraint(
            "system_id",
            "event_type",
            "threshold_days",
            "effective_eol_date",
            name="lifecycle_notification_state_unique_key",
        ),
        CheckConstraint(
            "event_type IN ('host_eol_approaching', 'host_eol_reached')",
            name="lifecycle_notification_state_event_type_valid",
        ),
        # Lookup hot path: emitter checks "have we already notified
        # this (system, event, threshold, eol_date)?" on every host
        # every day. The unique constraint above already covers this
        # composite, so no extra index is needed.
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type = Column(String(64), nullable=False)
    threshold_days = Column(Integer, nullable=False)
    effective_eol_date = Column(Date, nullable=False)
    notified_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    system = relationship("System")


class DistroLifecycleOverride(Base):  # pylint: disable=too-few-public-methods
    """Per-scope lifecycle override (PRA-156 #3e).

    When a smart group has an entitlement that extends a distro
    release's support window beyond the global ``distro_lifecycle``
    standard date — Ubuntu Pro / RHEL ELS / vendor extended-support
    contracts — the operator records that here. ``LifecycleService.compute``
    consults overrides for the system's smart-group memberships before
    falling back to the global standard row.

    Scope is ``smart_group`` for v1 by lock; ``scope_type`` carries
    forward to keep static-group / customer scope addable without a
    migration corner. The CHECK constraints below pin both fields to
    the v1-supported values so a future scope or support_kind addition
    is an explicit, documented schema change.

    Lookup precedence (mirrors the standard row): exact release wins
    over RHEL-family major fallback; among matching overrides, latest
    ``eol_date`` wins, then newest ``updated_at``, then highest ``id``
    as the deterministic tie-break.
    """

    __tablename__ = "distro_lifecycle_override"
    __table_args__ = (
        UniqueConstraint(
            "scope_type",
            "scope_id",
            "distro_id",
            "release",
            name="distro_lifecycle_override_unique_per_scope",
        ),
        CheckConstraint(
            "scope_type IN ('smart_group')",
            name="distro_lifecycle_override_scope_type_valid",
        ),
        CheckConstraint(
            "support_kind IN ('extended')",
            name="distro_lifecycle_override_support_kind_valid",
        ),
        # Scope-specific lookups (the compute path queries by
        # scope_type + scope_id + distro_id) hit this index. Standard
        # row lookup uses ix_distro_lifecycle_distro_release; overrides
        # need their own because the leading column is scope.
        Index(
            "ix_distro_lifecycle_override_scope",
            "scope_type",
            "scope_id",
            "distro_id",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    # ``scope_type`` is reserved for non-smart-group scopes (static
    # groups / customer accounts) without forcing a future migration.
    scope_type = Column(String(16), nullable=False)
    scope_id = Column(Integer, nullable=False)
    distro_id = Column(String(64), nullable=False)
    release = Column(String(64), nullable=False)
    eol_date = Column(Date, nullable=False)
    support_kind = Column(String(16), nullable=False)
    source = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class MirrorRepo(Base):  # pylint: disable=too-few-public-methods
    """Top-level mirror definition (PRA-157 slice #1).

    One row per (upstream_url, distribution) tuple. Distinct from
    ``RepoSource``: that's per-host repo config installed on a
    managed system; this is what Praxis pulls into local storage.

    Locks (project_pra157_design_locks.md):
      * ``package_family`` is 'deb' or 'rpm' — yum/dnf share rpm
        metadata.
      * ``source_mode`` flips to 'imported_offline' via the PRA-160
        importer; carved here so retrofit isn't needed.
      * ``deleted_at`` is LOCAL — soft-delete semantics stay scoped
        to mirror_repos and don't bleed into Base.
      * ``disk_budget_bytes`` nullable: unset = global free-space
        reserve is the only cap; set = per-mirror estimate gate
        becomes stricter.
      * ``sync_schedule_cron`` stores a cron string internally but
        the UI never exposes raw cron — feedback_no_cron.md.

    Sync history lives in ``MirrorSyncRun``. Alert dedup state lives
    in ``MirrorAlertState``.
    """

    __tablename__ = "mirror_repos"
    __table_args__ = (
        UniqueConstraint("slug", name="mirror_repos_slug_unique"),
        CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="mirror_repos_package_family_valid",
        ),
        CheckConstraint(
            "source_mode IN ('upstream_sync', 'imported_offline')",
            name="mirror_repos_source_mode_valid",
        ),
        CheckConstraint(
            "last_sync_status IN ('idle', 'running', 'ok', 'failed')",
            name="mirror_repos_last_sync_status_valid",
        ),
        CheckConstraint(
            "retention_keep_count >= 1",
            name="mirror_repos_retention_keep_count_positive",
        ),
        CheckConstraint(
            "retention_keep_within_days >= 0",
            name="mirror_repos_retention_keep_within_days_nonneg",
        ),
        CheckConstraint(
            "disk_budget_bytes IS NULL OR disk_budget_bytes > 0",
            name="mirror_repos_disk_budget_positive",
        ),
        CheckConstraint(
            "current_disk_bytes >= 0",
            name="mirror_repos_current_disk_bytes_nonneg",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False)
    display_name = Column(String(128), nullable=False)
    package_family = Column(String(8), nullable=False)
    upstream_url = Column(String(512), nullable=False)
    distribution = Column(String(64), nullable=False)
    # JSON-encoded string lists. apt mirrors carry components
    # (main, universe, ...); dnf mirrors typically have none and
    # store ``[]``. Architectures applies to both.
    components = Column(Text, nullable=False, default="[]")
    architectures = Column(Text, nullable=False, default="[]")
    sync_schedule_cron = Column(String(128), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    source_mode = Column(String(20), nullable=False, default="upstream_sync")
    verify_upstream_signature = Column(Boolean, nullable=False, default=True)
    retention_keep_count = Column(Integer, nullable=False, default=10)
    retention_keep_within_days = Column(Integer, nullable=False, default=30)
    disk_budget_bytes = Column(BigInteger, nullable=True)
    last_sync_started_at = Column(DateTime, nullable=True)
    last_sync_finished_at = Column(DateTime, nullable=True)
    last_sync_status = Column(String(16), nullable=False, default="idle")
    last_sync_error = Column(Text, nullable=True)
    current_disk_bytes = Column(BigInteger, nullable=False, default=0)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    sync_runs = relationship(
        "MirrorSyncRun",
        back_populates="mirror_repo",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alert_state = relationship(
        "MirrorAlertState",
        back_populates="mirror_repo",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class MirrorSyncRun(Base):  # pylint: disable=too-few-public-methods
    """One row per sync attempt (PRA-157 slice #1).

    UI calls all rows "sync history"; only ``status='ok'`` rows are
    surfaced as "snapshots / manifests." Single-table chosen over a
    runs+snapshots split during effort scoping — nullable manifest
    columns are easier to reason about than a second filter table.

    Service-level invariant (test in slice #1, no DB constraint):
      * status='ok'      → manifest fields + finished_at non-null
      * status='running' → manifest fields and finished_at all null
      * status='failed'  → manifest fields null; finished_at may be set

    ``estimate_unavailable`` is a slice-#2a column carved in now
    (true when the pre-sync estimate gate had no number to work
    with — first sync, dry-run failed, etc.).
    """

    __tablename__ = "mirror_sync_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'ok', 'failed')",
            name="mirror_sync_runs_status_valid",
        ),
        CheckConstraint(
            # PRA-160 slice #1: ``import`` added so the airgap
            # importer (slice #3) can land an ``ok`` row capturing
            # the imported mirror's manifest sha256 + byte count.
            # Imported runs are inserted as ``status='ok'`` directly
            # and are never scheduler-owned.
            "run_kind IN ('sync', 'sign_only', 'import')",
            name="mirror_sync_runs_run_kind_valid",
        ),
        Index(
            "ix_mirror_sync_runs_repo_started",
            "mirror_repo_id",
            "started_at",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mirror_repo_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(16), nullable=False)
    # PRA-158 #2a: explicit column distinguishing full-sync runs from
    # sign-only retrofits (sign_only is the slice #2c primitive that
    # signs whatever's currently in live/ without pulling upstream).
    # Status semantics from PRA-157 stay clean — running/ok/failed
    # mean the same thing for both kinds.
    run_kind = Column(String(16), nullable=False, default="sync")
    byte_count = Column(BigInteger, nullable=True)
    package_count = Column(Integer, nullable=True)
    manifest_sha256 = Column(String(64), nullable=True)
    manifest_path = Column(String(512), nullable=True)
    # PRA-158 #2a: detached signature sidecar for the manifest. NULL
    # on pre-PRA-158 rows and on rows produced before slice #2c wires
    # the signing engine. Locked: the signature does NOT feed back
    # into manifest_sha256 (the content fingerprint stays stable).
    manifest_signature_path = Column(String(512), nullable=True)
    # PRA-158 #2a: FK to the signing key used for native + manifest
    # signatures on this run. ON DELETE SET NULL so retiring a key
    # row doesn't cascade through sync history. NULL on pre-PRA-158
    # and #2a-only rows.
    signed_with_key_id = Column(
        Integer,
        ForeignKey("mirror_signing_keys.id", ondelete="SET NULL"),
        nullable=True,
    )
    error_text = Column(Text, nullable=True)
    estimate_unavailable = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    mirror_repo = relationship("MirrorRepo", back_populates="sync_runs")
    signed_with_key = relationship("MirrorSigningKey")
    indexed_packages = relationship(
        "MirrorSyncRunPackage",
        back_populates="sync_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class MirrorSyncRunPackage(Base):  # pylint: disable=too-few-public-methods
    """Derived per-package index for a successful ``MirrorSyncRun``
    (PRA-164 slice 3).

    One row per ``(mirror_sync_run_id, package_name, version, arch)``
    parsed from the on-disk manifest produced by
    ``mirror_manifest.build_manifest``. Populated inside the existing
    sync-completion path right after ``stage_signed_manifest`` runs;
    a scoped backfill helper handles successful runs that pre-date
    Slice 3 or were missed.

    The manifest file remains the source of truth. This index is
    purely derived and exists so PRA-164 preflight can answer
    "does mirror X publish package P at version V?" via SQL query
    rather than reading the manifest JSON every time. Read access
    at preflight time is DB-only — the resolver does NOT touch the
    filesystem.

    ``mirror_repo_id`` is denormalized (alongside the FK to
    ``mirror_sync_runs``) so the per-mirror "is this name+version
    indexed?" query stays a single composite-index lookup. Both
    FKs are ``ON DELETE CASCADE`` so retention sweeps and mirror
    deletions don't leave orphan index rows.
    """

    __tablename__ = "mirror_sync_run_packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mirror_sync_run_id = Column(
        Integer,
        ForeignKey("mirror_sync_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    mirror_repo_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_name = Column(String(255), nullable=False)
    version = Column(String(255), nullable=False)
    arch = Column(String(64), nullable=True)
    filename = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False)
    size = Column(BigInteger, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    sync_run = relationship("MirrorSyncRun", back_populates="indexed_packages")
    mirror_repo = relationship("MirrorRepo", foreign_keys=[mirror_repo_id])

    __table_args__ = (
        UniqueConstraint(
            "mirror_sync_run_id",
            "package_name",
            "version",
            "arch",
            name="uq_mirror_sync_run_packages_target",
        ),
        Index(
            "ix_mirror_sync_run_packages_repo_name_version",
            "mirror_repo_id",
            "package_name",
            "version",
        ),
        Index(
            "ix_mirror_sync_run_packages_run",
            "mirror_sync_run_id",
        ),
        # Slice 3a fix: closes the PostgreSQL
        # NULL-distinct gap for null-arch rows so the full UNIQUE
        # above is real for every row.
        Index(
            "uq_mirror_sync_run_packages_no_arch",
            "mirror_sync_run_id",
            "package_name",
            "version",
            unique=True,
            postgresql_where=sa_text("arch IS NULL"),
        ),
    )


class MirrorAlertState(Base):  # pylint: disable=too-few-public-methods
    """Dedup state for mirror-engine alert events (PRA-157 slice #1).

    Mirrors PRA-156's ``LifecycleNotificationState`` shape — an
    upstream "did we already notify?" gate consulted before the
    alert path calls ``alert_service.send_alert``. Slice #2b is the
    first writer; the table lives in #1 so the alert plumbing slice
    has no migration to add.

    Cooldown logic compares ``last_fired_at`` against the configured
    cooldown (default 24h) before firing again for the same
    (mirror_repo_id, event_type) pair.
    """

    __tablename__ = "mirror_alert_state"
    __table_args__ = (
        UniqueConstraint(
            "mirror_repo_id",
            "event_type",
            name="mirror_alert_state_unique_key",
        ),
        CheckConstraint(
            "event_type IN ("
            "'mirror_sync_failed', "
            "'mirror_sync_completed', "
            "'mirror_disk_pressure', "
            "'mirror_upstream_signature_invalid'"
            ")",
            name="mirror_alert_state_event_type_valid",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mirror_repo_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type = Column(String(64), nullable=False)
    last_fired_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    mirror_repo = relationship("MirrorRepo", back_populates="alert_state")


class MirrorSigningKey(Base):  # pylint: disable=too-few-public-methods
    """Per-mirror GPG signing key (PRA-158 slice #1).

    DB row stores fingerprint + uid + status + Vault path; armored
    private + public material lives in Vault at
    ``praxis/mirror-signing-keys/<mirror_slug>/<gpg_fingerprint>``.

    Status machine (slice #5 wires the rotation transitions):
      * ``active`` — key currently used to sign native metadata + manifest.
      * ``pending_cutover`` — newly generated for an in-flight rotation;
        included in the public trust bundle so hosts can install ahead
        of cutover, but NOT used for signing yet.
      * ``rotating_out`` — was active before the most recent cutover;
        still in the trust bundle so hosts that haven't reinstalled yet
        keep working, NOT used for signing.
      * ``retired`` — dropped from the trust bundle entirely.

    Invariants (DB-enforced via partial unique indexes — slice #1-a):
      * at most one ``active`` per mirror_repo_id
      * at most one ``pending_cutover`` per mirror_repo_id

    Concurrent bootstrap calls that both try to insert ``active`` will
    one win and one IntegrityError; the service catches and re-fetches.
    Multiple ``rotating_out`` and ``retired`` rows ARE allowed (a mirror
    accumulates retired keys across rotations).
    """

    __tablename__ = "mirror_signing_keys"
    __table_args__ = (
        UniqueConstraint(
            "gpg_fingerprint",
            name="mirror_signing_keys_fingerprint_unique",
        ),
        CheckConstraint(
            "status IN ('active', 'pending_cutover', 'rotating_out', 'retired')",
            name="mirror_signing_keys_status_valid",
        ),
        Index(
            "ix_mirror_signing_keys_repo_status",
            "mirror_repo_id",
            "status",
        ),
        Index(
            "uq_mirror_signing_keys_one_active_per_mirror",
            "mirror_repo_id",
            unique=True,
            postgresql_where=sa_text("status = 'active'"),
        ),
        Index(
            "uq_mirror_signing_keys_one_pending_per_mirror",
            "mirror_repo_id",
            unique=True,
            postgresql_where=sa_text("status = 'pending_cutover'"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mirror_repo_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    status = Column(String(20), nullable=False)
    gpg_fingerprint = Column(String(64), nullable=False)
    key_uid = Column(String(255), nullable=False)
    vault_path = Column(String(255), nullable=False)
    # PRA-158 #3a: armored public key cached on the row so trust-bundle
    # reads (slice #3b) don't pull private material out of Vault on
    # every fetch. Nullable for backward compat with slice #1 rows that
    # predate this column; service backfills lazily on first read.
    armored_public_key = Column(Text, nullable=True)
    cutover_at = Column(DateTime, nullable=True)
    retired_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    mirror_repo = relationship("MirrorRepo")


class HostMirrorTrust(Base):  # pylint: disable=too-few-public-methods
    """Per (host, mirror) record of installed signing-key fingerprints
    (PRA-158 #3a).

    Updated by slice #3c's ``install_mirror_trust`` primitive after a
    successful host-side install. Read by:
      * slice #5's cutover hard-gate, which refuses cutover if any
        host's installed_fingerprints set lacks the pending key.
      * UI list views surfacing trust drift.

    JSONB ``installed_fingerprints`` chosen over Postgres ARRAY per
    the praxis-wide convention (see project_pra158_design_locks.md
    "host_mirror_trust" lock). Empty list is the bootstrap state.
    """

    __tablename__ = "host_mirror_trust"
    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "mirror_id",
            name="host_mirror_trust_host_mirror_unique",
        ),
        Index("ix_host_mirror_trust_mirror", "mirror_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    host_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    mirror_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    installed_fingerprints = Column(JSONB, nullable=False, default=list)
    last_installed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    mirror = relationship("MirrorRepo")


class MirrorUpstreamKey(Base):  # pylint: disable=too-few-public-methods
    """Praxis-wide trust anchor for verifying upstream repo signatures
    (PRA-158 #4a).

    Stores armored PUBLIC keys for upstream archive signing keys
    (Ubuntu Archive, Debian, Rocky, Alma, CentOS Stream, RHEL).
    Public material lives in DB directly, NOT Vault — these are not
    secrets and Vault would only add blast-radius without protection.

    Slice #4b's pre-sync gate builds a transient gpg keyring from
    these rows and verifies upstream ``Release.gpg`` / ``repomd.xml.asc``
    against it before allowing the sync to proceed.
    """

    __tablename__ = "mirror_upstream_keys"
    __table_args__ = (
        UniqueConstraint(
            "gpg_fingerprint",
            name="mirror_upstream_keys_fingerprint_unique",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    gpg_fingerprint = Column(String(64), nullable=False)
    armored_public_key = Column(Text, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


# ---------------------------------------------------------------------------
# PRA-159: content channels + profiles + subscriptions
# ---------------------------------------------------------------------------


class ContentChannel(Base):  # pylint: disable=too-few-public-methods
    """Content composition (PRA-159 slice #1).

    A channel bundles one-or-more mirrors of the same
    ``package_family``. Hosts do NOT subscribe to channels directly —
    they subscribe to ``ContentProfile`` rows that compose channels.
    M16 patch policy will bind to channels.

    Locks (PRA-159 design conversation):
      * ``package_family`` ∈ ``deb | rpm`` and must agree with every
        ``ContentChannelRepo`` mirror it composes.
      * ``deleted_at`` is local soft-delete (mirrors PRA-157
        ``mirror_repos`` pattern). Resolver / list views filter
        deleted rows.
      * Slug is immutable post-create; rename via display_name.
    """

    __tablename__ = "content_channels"
    __table_args__ = (
        UniqueConstraint("slug", name="content_channels_slug_unique"),
        CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="content_channels_package_family_valid",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False)
    display_name = Column(String(128), nullable=False)
    package_family = Column(String(8), nullable=False)
    description = Column(Text, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    repos = relationship(
        "ContentChannelRepo",
        back_populates="channel",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ContentChannelRepo(Base):  # pylint: disable=too-few-public-methods
    """One mirror entry inside a channel (PRA-159 slice #1).

    ``suite_override`` lets a channel compose multiple suites of the
    same upstream (e.g. ``jammy + jammy-security + jammy-updates``)
    without forcing three separate ``mirror_repos`` rows. ``NULL``
    means "use the mirror's own ``distribution`` as the suite."

    ``pinned_run_id`` is **manifest pin / tracking pin** — metadata
    only. Bytes always come from the mirror's ``live/`` tree; a pin
    asserts "channel content was equal to manifest sha X at pin
    time," not "content is frozen at X." True byte freeze rides
    PRA-160 export → re-import as ``imported_offline``.

    Uniqueness:
      * ``(channel_id, mirror_id, suite_override)`` triple-unique
      * Partial unique on ``(channel_id, mirror_id) WHERE
        suite_override IS NULL`` — only one inherit-suite entry per
        ``(channel, mirror)`` is meaningful (Postgres NULLs are
        distinct so the triple alone doesn't catch this).
    """

    __tablename__ = "content_channel_repos"
    __table_args__ = (
        UniqueConstraint(
            "channel_id",
            "mirror_id",
            "suite_override",
            name="content_channel_repos_unique_triple",
        ),
        Index(
            "ux_content_channel_repos_inherit_suite",
            "channel_id",
            "mirror_id",
            unique=True,
            postgresql_where=sa_text("suite_override IS NULL"),
        ),
        Index("ix_content_channel_repos_mirror", "mirror_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    channel_id = Column(
        Integer,
        ForeignKey("content_channels.id", ondelete="CASCADE"),
        nullable=False,
    )
    mirror_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    suite_override = Column(String(64), nullable=True)
    pinned_run_id = Column(
        Integer,
        ForeignKey("mirror_sync_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    channel = relationship("ContentChannel", back_populates="repos")
    mirror = relationship("MirrorRepo")
    pinned_run = relationship("MirrorSyncRun")


class ContentProfile(Base):  # pylint: disable=too-few-public-methods
    """Desired host source configuration (PRA-159 slice #1).

    The host-facing object: hosts (or groups, or smart groups)
    subscribe to a profile, and Praxis writes one source-list file
    per effective profile per host. A profile composes one or more
    channels via ``content_profile_channels`` (M:N).

    Locks:
      * ``package_family`` must agree with every channel it composes
        AND every effective subscriber (apt host can't subscribe to
        an rpm profile — service-level enforcement at apply time).
      * ``deleted_at`` is local soft-delete.
      * Resolution returns one of ``no_profile | resolved | conflict``
        — see ``ContentProfileService.resolve_effective``.
    """

    __tablename__ = "content_profiles"
    __table_args__ = (
        UniqueConstraint("slug", name="content_profiles_slug_unique"),
        CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="content_profiles_package_family_valid",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False)
    display_name = Column(String(128), nullable=False)
    package_family = Column(String(8), nullable=False)
    description = Column(Text, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    channel_links = relationship(
        "ContentProfileChannel",
        back_populates="profile",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ContentProfileChannel(Base):  # pylint: disable=too-few-public-methods
    """Profile↔channel composition (PRA-159 slice #1)."""

    __tablename__ = "content_profile_channels"
    __table_args__ = (
        UniqueConstraint(
            "profile_id",
            "channel_id",
            name="content_profile_channels_unique_pair",
        ),
        Index("ix_content_profile_channels_channel", "channel_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    profile_id = Column(
        Integer,
        ForeignKey("content_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    channel_id = Column(
        Integer,
        ForeignKey("content_channels.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    profile = relationship("ContentProfile", back_populates="channel_links")
    channel = relationship("ContentChannel")


class HostContentProfileSubscription(Base):  # pylint: disable=too-few-public-methods
    """Direct host→profile subscription (PRA-159 slice #1).

    Highest precedence in ``ContentProfileService.resolve_effective``.
    Multiple direct subscriptions per host ARE legal at the schema
    level; the resolver surfaces multi-subscription as
    ``conflict`` so operators see ambiguity loud.
    """

    __tablename__ = "host_content_profile_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "profile_id",
            name="host_content_profile_subs_unique_pair",
        ),
        Index("ix_host_content_profile_subs_profile", "profile_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    host_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    profile_id = Column(
        Integer,
        ForeignKey("content_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    host = relationship("System")
    profile = relationship("ContentProfile")


class GroupContentProfileSubscription(Base):  # pylint: disable=too-few-public-methods
    """Static-group→profile subscription (PRA-159 slice #1).

    Middle precedence (after direct, before smart-group).
    """

    __tablename__ = "group_content_profile_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "group_id",
            "profile_id",
            name="group_content_profile_subs_unique_pair",
        ),
        Index("ix_group_content_profile_subs_profile", "profile_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    group_id = Column(
        Integer,
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    profile_id = Column(
        Integer,
        ForeignKey("content_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    group = relationship("Group")
    profile = relationship("ContentProfile")


class SmartGroupContentProfileSubscription(
    Base
):  # pylint: disable=too-few-public-methods
    """Smart-group→profile subscription (PRA-159 slice #1).

    Lowest precedence. Resolver walks
    ``SmartGroupMembership`` to find which smart groups a host
    belongs to, then looks up subscriptions on those.
    """

    __tablename__ = "smart_group_content_profile_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "smart_group_id",
            "profile_id",
            name="smart_group_content_profile_subs_unique_pair",
        ),
        Index("ix_smart_group_content_profile_subs_profile", "profile_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    smart_group_id = Column(
        Integer,
        ForeignKey("smart_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    profile_id = Column(
        Integer,
        ForeignKey("content_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    smart_group = relationship("SmartGroup")
    profile = relationship("ContentProfile")


class HostMirrorServeCredential(Base):  # pylint: disable=too-few-public-methods
    """Per-(host, mirror) bearer credential for the mirror serve
    endpoint (PRA-159 slice #2).

    Plaintext is returned ONCE at issue time and never stored. The
    ``token_hash`` column stores a passlib pbkdf2_sha256 hash;
    ``MirrorServeCredentialService.verify`` hashes the presented
    bearer and looks up by hash.

    Locks:
      * At most one active credential per ``(host_id, mirror_id)``
        — partial unique index ``WHERE revoked_at IS NULL``.
        ``issue`` revokes the prior active row before inserting in
        a single short transaction; the partial index is the DB belt.
      * ``token_hash`` has NO unique index — pbkdf2_sha256 is
        per-row salted so two rows with the same plaintext hash to
        different strings; uniqueness wouldn't catch the duplicate
        and the verifier doesn't look up by hash. The verifier
        scans candidate rows.
      * ``expires_at`` is a wall-clock TTL; verifier rejects expired
        rows even if not explicitly revoked.
      * ``last_used_at`` is best-effort (last-write-wins under
        contention is fine for an "approximate last use" diagnostic).
    """

    __tablename__ = "host_mirror_serve_credentials"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    host_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    mirror_id = Column(
        Integer,
        ForeignKey("mirror_repos.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash = Column(String(255), nullable=False)
    # PRA-180 MIRROR-01: public, non-secret lookup id embedded as the prefix of
    # the plaintext bearer (``<token_id>.<secret>``). Indexed so verify() finds
    # the single matching row and runs pbkdf2 once, instead of scanning every
    # active credential fleet-wide. Nullable so credentials issued before this
    # column existed (legacy plaintext with no ``.`` separator) still verify via
    # the bounded ``token_id IS NULL`` fallback scan.
    token_id = Column(String(64), nullable=True, index=True)
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    host = relationship("System")
    mirror = relationship("MirrorRepo")


# ---------------------------------------------------------------------------
# PRA-160: airgap export/import substrate
# ---------------------------------------------------------------------------


class AirgapBundleSigningKey(Base):  # pylint: disable=too-few-public-methods
    """Instance-wide airgap-bundle GPG signing key (PRA-160 slice #1).

    Distinct from ``MirrorSigningKey`` (per-mirror) — this key signs
    the bundle descriptor itself, proving "this Praxis instance built
    this bundle." Per-mirror manifest signatures ride along inside the
    bundle untouched and chain through the descriptor's declared
    fingerprint/public-key fields (those fields are covered by the
    bundle signature).

    Status machine (slice #1 only writes ``active``):
      * ``active`` — current key.
      * ``rotating_out`` — replaced by a newer active key but still
        retained for verification of older bundles.
      * ``retired`` — fully retired; no longer trusted.

    Invariant (DB-enforced via partial unique index):
      * at most one ``active`` row per Praxis instance.

    Material:
      * Vault path: ``praxis/bundle-signing-key/<gpg_fingerprint>``.
      * ``armored_public_key`` cached on the row (PRA-158 #3a pattern)
        so import-side / verify-side reads never touch private
        material.
    """

    __tablename__ = "airgap_bundle_signing_keys"
    __table_args__ = (
        UniqueConstraint(
            "gpg_fingerprint",
            name="airgap_bundle_signing_keys_fingerprint_unique",
        ),
        CheckConstraint(
            "status IN ('active', 'rotating_out', 'retired')",
            name="airgap_bundle_signing_keys_status_valid",
        ),
        Index(
            "uq_airgap_bundle_signing_keys_one_active",
            "status",
            unique=True,
            postgresql_where=sa_text("status = 'active'"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    status = Column(String(20), nullable=False)
    gpg_fingerprint = Column(String(64), nullable=False)
    key_uid = Column(String(255), nullable=False)
    vault_path = Column(String(255), nullable=False)
    armored_public_key = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AirgapBundle(Base):  # pylint: disable=too-few-public-methods
    """One airgap bundle built on this Praxis instance (PRA-160 slice #1).

    Locks (PRA-160 design conversation):
      * ``kind`` ∈ ``full | delta`` from day one — describes the
        eventual bundle semantics, not slice progress. Slice #1 only
        emits descriptor-only rows but the kind column is set
        correctly at insert time so a slice #1 row can resume in
        slice #2 without a column update.
      * ``status`` ∈ ``building | descriptor_ready | ok | failed``.
        Slice #1 transitions ``building → descriptor_ready`` after
        the descriptor signature lands. Slice #2 picks up from
        ``descriptor_ready`` and reaches ``ok`` after tar assembly +
        payload sha + descriptor re-sign.
      * Path naming: ``bundle_descriptor_path`` (the JSON + sig live
        in this directory under ``.airgap-staging/<bundle_id>/``);
        ``bundle_path`` is the eventual final tar file (slice #2).
        Never use ``manifest_*`` or ``payload_path`` here — those
        names are reserved for mirror manifests / would conflict with
        the descriptor's own ``payload_index`` body.
      * Planner-validation refusals do NOT create a row; only
        accepted requests get one.

    Subtle DB rule (CheckConstraint
    ``airgap_bundles_parent_matches_kind``):
      * ``kind='full'``  → ``parent_bundle_id IS NULL``.
      * ``kind='delta'`` → ``parent_bundle_id IS NOT NULL``.
    """

    __tablename__ = "airgap_bundles"
    __table_args__ = (
        UniqueConstraint("bundle_id", name="airgap_bundles_bundle_id_unique"),
        CheckConstraint(
            "kind IN ('full', 'delta')",
            name="airgap_bundles_kind_valid",
        ),
        CheckConstraint(
            "status IN ('building', 'descriptor_ready', 'ok', 'failed')",
            name="airgap_bundles_status_valid",
        ),
        CheckConstraint(
            "(kind = 'full' AND parent_bundle_id IS NULL) "
            "OR (kind = 'delta' AND parent_bundle_id IS NOT NULL)",
            name="airgap_bundles_parent_matches_kind",
        ),
        Index(
            "ix_airgap_bundles_status_created",
            "status",
            "created_at",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    bundle_id = Column(String(64), nullable=False)
    kind = Column(String(16), nullable=False)
    parent_bundle_id = Column(String(64), nullable=True)
    status = Column(String(24), nullable=False)
    bundle_descriptor_path = Column(String(512), nullable=True)
    bundle_path = Column(String(512), nullable=True)
    payload_sha256 = Column(String(64), nullable=True)
    byte_count = Column(BigInteger, nullable=True)
    signing_key_id = Column(
        Integer,
        ForeignKey("airgap_bundle_signing_keys.id", ondelete="SET NULL"),
        nullable=True,
    )
    request_payload = Column(Text, nullable=True)
    error_text = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    signing_key = relationship("AirgapBundleSigningKey")


class AirgapImport(Base):  # pylint: disable=too-few-public-methods
    """One airgap bundle imported into this Praxis instance (PRA-160).

    Slice #1 ships the table; slice #3's importer is the only writer.
    A row is inserted at the start of an import attempt
    (``status='verifying'``) and transitions through
    ``verifying → extracting → ok`` (or ``failed`` from any prior
    step). ``bundle_id`` is the public bundle id from the export
    side's descriptor — used by the importer for idempotency
    (re-import of the same bundle_id is rejected unless
    ``--re-import`` is set, slice #3 lock).
    """

    __tablename__ = "airgap_imports"
    __table_args__ = (
        UniqueConstraint("bundle_id", name="airgap_imports_bundle_id_unique"),
        CheckConstraint(
            "kind IN ('full', 'delta')",
            name="airgap_imports_kind_valid",
        ),
        CheckConstraint(
            "status IN ('verifying', 'extracting', 'ok', 'failed')",
            name="airgap_imports_status_valid",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    bundle_id = Column(String(64), nullable=False)
    parent_bundle_id = Column(String(64), nullable=True)
    kind = Column(String(16), nullable=False)
    status = Column(String(16), nullable=False)
    payload_sha256 = Column(String(64), nullable=True)
    byte_count = Column(BigInteger, nullable=True)
    error_text = Column(Text, nullable=True)
    # PRA-160 slice #3: source tar path on disk; populated by the
    # importer at row insert. Forensic aid for failed-import rows.
    path = Column(String(1024), nullable=True)
    # PRA-160 slice #3: prefixed mirror slugs created (or attempted
    # to create) by this import. JSONB list of strings.
    target_mirror_slugs = Column(JSONB, nullable=False, default=list)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AirgapImportTrustKey(Base):  # pylint: disable=too-few-public-methods
    """Operator-pinned bundle public keys (PRA-160 slice #3).

    The importer verifies ``bundle.json.sig`` against keys in this
    table — never against armored bytes carried inside the tar.
    Operator pins keys via
    ``POST /airgap/import-trust`` after receiving the public key
    out-of-band from the export side.

    Locks:
      * ``gpg_fingerprint`` is unique among active rows (partial
        unique index ``WHERE deleted_at IS NULL``). A key may be
        re-pinned after soft-delete — that produces a fresh row
        with a new ``added_at`` for audit clarity.
      * Soft-delete via ``deleted_at``. Verifier filters
        ``deleted_at IS NULL``. Soft-deleted rows remain for audit
        retention so an operator can answer "did we ever trust
        fingerprint X?" months after revocation.
      * ``armored_public_key`` is non-secret (public material) —
        stored in DB, not Vault.
    """

    __tablename__ = "airgap_import_trust_keys"
    __table_args__ = (
        Index(
            "uq_airgap_import_trust_keys_active_fingerprint",
            "gpg_fingerprint",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    gpg_fingerprint = Column(String(64), nullable=False)
    key_uid = Column(String(255), nullable=False)
    armored_public_key = Column(Text, nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
