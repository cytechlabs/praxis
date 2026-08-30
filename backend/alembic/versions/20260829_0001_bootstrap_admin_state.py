"""Record that an installation has completed first-run initialization.

Startup provisions the bootstrap administrator when no user carries the
configured username, so an administrator that was deliberately deleted came
back on the next restart, with the admin role and the password still sitting in
the environment. Renaming the account, or changing the configured username, had
the same effect through the same gate.

``bootstrap_admin_state`` holds one row recording that this installation has
been initialized. The fact is about the installation, not about an account, so
it stays true after the account it describes is deleted, renamed, disabled, or
stripped of its role. ``bootstrap_user_id`` nulls out when that account is
deleted and the row remains.

This revision creates the table and nothing else. Whether an existing database
counts as already initialized is decided on its next startup, by the
initializer, which is where the decision can be tested and audited: an
installation that already has users is recorded as initialized without
provisioning anything, and one with no users at all has no reachable login and
is provisioned exactly as before.

A database downgraded past this revision loses the record. Re-upgrading
re-derives it from the same rule, so a deleted administrator stays deleted as
long as any user remains. Running the older code again does not: that release
recreates the account whenever the configured username is absent and
ADMIN_PASSWORD is set. Clearing ADMIN_PASSWORD once the first administrator has
signed in is what makes that rollback safe.

Revision ID: bootstrap_admin_state
Revises: system_onboarding_drafts
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bootstrap_admin_state"
down_revision: Union[str, None] = "system_onboarding_drafts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bootstrap_admin_state",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # Always the literal "bootstrap_admin". The check and the unique
        # constraint below are what make "at most one row" a database fact,
        # and together they are the backstop that keeps two backends racing
        # through their first boot from both provisioning.
        sa.Column("marker", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("bootstrap_user_id", sa.Integer(), nullable=True),
        sa.Column("bootstrap_username", sa.String(length=200), nullable=True),
        sa.Column("initialized_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        # Uniqueness alone would allow any number of rows under different
        # marker strings. The reader looks for one literal, so those rows would
        # be invisible to it and a first boot would provision over the top of a
        # record that already said this installation was initialized. Pinning
        # the column to that literal is what makes uniqueness mean one row.
        sa.CheckConstraint(
            "marker = 'bootstrap_admin'", name="ck_bootstrap_admin_state_marker"
        ),
        sa.UniqueConstraint("marker", name="uq_bootstrap_admin_state_marker"),
        # The record outlives the account: deleting the user nulls the
        # reference instead of removing the row that says this installation was
        # initialized.
        sa.ForeignKeyConstraint(
            ["bootstrap_user_id"], ["user.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        op.f("ix_bootstrap_admin_state_id"),
        "bootstrap_admin_state",
        ["id"],
    )
    op.create_index(
        op.f("ix_bootstrap_admin_state_bootstrap_user_id"),
        "bootstrap_admin_state",
        ["bootstrap_user_id"],
    )


def downgrade() -> None:
    """Drop the record only. No user, role, or credential is touched."""
    op.drop_index(
        op.f("ix_bootstrap_admin_state_bootstrap_user_id"),
        table_name="bootstrap_admin_state",
    )
    op.drop_index(
        op.f("ix_bootstrap_admin_state_id"), table_name="bootstrap_admin_state"
    )
    op.drop_table("bootstrap_admin_state")
