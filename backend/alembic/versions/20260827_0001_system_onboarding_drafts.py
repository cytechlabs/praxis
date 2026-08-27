"""Guided onboarding drafts, system description, and unique system IP.

Three related changes behind the guided Add System flow:

1. ``system_onboarding_drafts`` holds the short-lived, operator-private draft a
   guided onboarding session works in, so no managed host is created until the
   operator finishes.
2. ``systems.description`` gives the description operators already type a place
   to live. It was previously accepted by the API and discarded.
3. ``systems.ip_address`` gains a unique constraint. The API already rejects a
   duplicate address, but only in Python, so two concurrent registrations could
   race past it. Enforcing it in the database makes the invariant real.

Both destructive directions fail closed rather than discarding operator data:
the upgrade refuses to run while duplicate addresses exist, and the downgrade
refuses to drop a description column that holds text.

Revision ID: system_onboarding_drafts
Revises: audit_event_host_attribution
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "system_onboarding_drafts"
down_revision: Union[str, None] = "audit_event_host_attribution"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


IP_UNIQUE_CONSTRAINT = "systems_ip_address_key"

# Duplicate addresses are reported rather than resolved. Merging two hosts or
# deleting one is an operator decision about real inventory, and a migration is
# the wrong place to make it silently.
_DUPLICATE_IP_HELP = (
    "Cannot add the unique constraint on systems.ip_address while duplicate "
    "addresses exist. Praxis already treats a duplicate address as invalid, so "
    "these rows predate that rule or were created concurrently. Resolve each "
    "address below by decommissioning or correcting the duplicate hosts, then "
    "re-run this migration. No data has been changed."
)

_DESCRIPTION_HELP = (
    "Cannot drop systems.description because {count} system(s) have a "
    "description stored. Dropping the column would destroy operator-entered "
    "text. Clear those descriptions deliberately if you intend to lose them, "
    "then re-run this downgrade. No data has been changed."
)


def _duplicate_ip_report(conn) -> str:
    """Build an actionable report of duplicated addresses, bounded in size."""
    rows = conn.execute(sa.text("""
            SELECT ip_address::text AS ip, count(*) AS n,
                   string_agg(hostname, ', ' ORDER BY hostname) AS hostnames
            FROM systems
            GROUP BY ip_address
            HAVING count(*) > 1
            ORDER BY count(*) DESC, ip_address
            LIMIT 20
            """)).fetchall()
    if not rows:
        return ""
    lines = [f"  {row.ip} used by {row.n} systems: {row.hostnames}" for row in rows]
    return "\n".join(lines)


def upgrade() -> None:
    conn = op.get_bind()

    report = _duplicate_ip_report(conn)
    if report:
        raise RuntimeError(f"{_DUPLICATE_IP_HELP}\n{report}")

    op.add_column("systems", sa.Column("description", sa.Text(), nullable=True))
    op.create_unique_constraint(IP_UNIQUE_CONSTRAINT, "systems", ["ip_address"])

    op.create_table(
        "system_onboarding_drafts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("public_id", sa.String(length=43), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=False),
        sa.Column("actor_authority_digest", sa.String(length=64), nullable=False),
        sa.Column("actor_scope_kind", sa.String(length=16), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column(
            "current_step",
            sa.String(length=16),
            server_default=sa.text("'connect'"),
            nullable=False,
        ),
        sa.Column(
            "state_version",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("finalize_token_hash", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(), nullable=False),
        sa.Column("finalizing_since", sa.DateTime(), nullable=True),
        sa.Column(
            "connection",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "organization",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "verification", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("discovery", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("host_key_type", sa.String(length=50), nullable=True),
        sa.Column("host_key_public", sa.Text(), nullable=True),
        sa.Column("host_key_fingerprint", sa.String(length=255), nullable=True),
        sa.Column(
            "host_key_decision",
            sa.String(length=16),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "verification_skipped",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("ssh_security_policy_id", sa.Integer(), nullable=True),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("distro_id", sa.Integer(), nullable=True),
        sa.Column("finalized_system_id", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("canceled_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["credentials.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["ssh_security_policy_id"],
            ["ssh_security_policies.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["distro_id"], ["distros.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["finalized_system_id"], ["systems.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "public_id", name="system_onboarding_drafts_public_id_uniq"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'finalizing', 'completed', 'canceled', 'expired')",
            name="system_onboarding_drafts_status_check",
        ),
        sa.CheckConstraint(
            "current_step IN ('connect', 'authenticate', 'verify', 'discover', "
            "'organize', 'confirm', 'finish')",
            name="system_onboarding_drafts_step_check",
        ),
        sa.CheckConstraint(
            "host_key_decision IN ('pending', 'trusted', 'rejected')",
            name="system_onboarding_drafts_host_key_decision_check",
        ),
        sa.CheckConstraint(
            "actor_scope_kind IN ('tenant_wide', 'scoped')",
            name="system_onboarding_drafts_scope_kind_check",
        ),
    )
    op.create_index(
        op.f("ix_system_onboarding_drafts_id"),
        "system_onboarding_drafts",
        ["id"],
    )
    op.create_index(
        "ix_system_onboarding_drafts_actor_status",
        "system_onboarding_drafts",
        ["actor_user_id", "status"],
    )
    op.create_index(
        "ix_system_onboarding_drafts_expires_at",
        "system_onboarding_drafts",
        ["expires_at"],
    )


def downgrade() -> None:
    conn = op.get_bind()

    # Checked before anything is dropped so a refusal costs no work and leaves
    # the schema exactly as it was.
    described = conn.execute(
        sa.text("SELECT count(*) FROM systems WHERE description IS NOT NULL")
    ).scalar()
    if described:
        raise RuntimeError(_DESCRIPTION_HELP.format(count=described))

    op.drop_index(
        "ix_system_onboarding_drafts_expires_at",
        table_name="system_onboarding_drafts",
    )
    op.drop_index(
        "ix_system_onboarding_drafts_actor_status",
        table_name="system_onboarding_drafts",
    )
    op.drop_index(
        op.f("ix_system_onboarding_drafts_id"),
        table_name="system_onboarding_drafts",
    )
    op.drop_table("system_onboarding_drafts")

    op.drop_constraint(IP_UNIQUE_CONSTRAINT, "systems", type_="unique")
    op.drop_column("systems", "description")
