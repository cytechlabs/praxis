"""PRA-159 slice #1: content channels + profiles + subscriptions.

Two host-facing nouns:

  * ``content_channels`` — pure content composition. A channel bundles
    one or more mirrors of the same ``package_family``. Each
    ``(channel, mirror)`` entry may carry a ``suite_override`` (so a
    channel can compose ``jammy + jammy-security + jammy-updates`` of
    the same upstream into one stream) and an optional
    ``pinned_run_id`` (manifest/tracking pin — metadata only; bytes
    always come from the mirror's ``live/`` tree).
  * ``content_profiles`` — desired host source configuration. A
    profile composes one or more channels (M:N via
    ``content_profile_channels``) and is what hosts subscribe to.

Subscriptions ride three parallel join tables matching the
PRA-155/PRA-156 convention (direct, static-group, smart-group).
``ContentProfileService.resolve_effective`` walks them with strict
precedence (direct > group > smart-group) and returns one of
``no_profile | resolved | conflict`` — apply refuses on conflict.

Design constraints for content channels and profiles:

  * ``package_family`` is mirror's vocabulary (``deb`` | ``rpm``); a
    channel and all its repos must agree, a profile and all its
    channels must agree.
  * ``deleted_at`` is local soft-delete on channel and profile, mirror
    of the PRA-157 ``mirror_repos`` pattern. Don't add to Base.
  * ``pinned_run_id`` is ``ON DELETE SET NULL`` so retiring sync runs
    doesn't cascade-poison channels that referenced them; the next
    pin operation re-asserts intent.
  * ``content_channel_repos`` uniqueness: ``(channel_id, mirror_id,
    suite_override)`` is unique, but Postgres treats ``NULL`` as
    distinct from ``NULL``. A partial unique index on
    ``(channel_id, mirror_id) WHERE suite_override IS NULL`` enforces
    "at most one inherit-suite entry per (channel, mirror)" while
    still allowing multi-suite composition when override is set.
  * Subscription tables use ``UniqueConstraint`` on ``(scope_id,
    profile_id)``; a host may legally have multiple direct
    subscriptions (the resolver surfaces this as ``conflict``).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra159_content_channels"
down_revision: Union[str, None] = "pra158_upstream_alert"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _ts_columns() -> list:
    return [
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    ]


def upgrade() -> None:
    # ---- content_channels --------------------------------------------------
    op.create_table(
        "content_channels",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("package_family", sa.String(8), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
        *_ts_columns(),
        sa.UniqueConstraint("slug", name="content_channels_slug_unique"),
        sa.CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="content_channels_package_family_valid",
        ),
    )

    # ---- content_channel_repos --------------------------------------------
    op.create_table(
        "content_channel_repos",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "channel_id",
            sa.Integer,
            sa.ForeignKey("content_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mirror_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("suite_override", sa.String(64), nullable=True),
        sa.Column(
            "pinned_run_id",
            sa.Integer,
            sa.ForeignKey("mirror_sync_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        *_ts_columns(),
        sa.UniqueConstraint(
            "channel_id",
            "mirror_id",
            "suite_override",
            name="content_channel_repos_unique_triple",
        ),
    )
    # Partial unique: when suite_override is NULL, only one inherit-
    # suite entry per (channel, mirror) is allowed. The full triple
    # uniqueness above does not catch this case because Postgres
    # NULLs are distinct.
    op.create_index(
        "ux_content_channel_repos_inherit_suite",
        "content_channel_repos",
        ["channel_id", "mirror_id"],
        unique=True,
        postgresql_where=sa.text("suite_override IS NULL"),
    )
    op.create_index(
        "ix_content_channel_repos_mirror",
        "content_channel_repos",
        ["mirror_id"],
    )

    # ---- content_profiles --------------------------------------------------
    op.create_table(
        "content_profiles",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("package_family", sa.String(8), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
        *_ts_columns(),
        sa.UniqueConstraint("slug", name="content_profiles_slug_unique"),
        sa.CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="content_profiles_package_family_valid",
        ),
    )

    # ---- content_profile_channels (M:N) -----------------------------------
    op.create_table(
        "content_profile_channels",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "profile_id",
            sa.Integer,
            sa.ForeignKey("content_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "channel_id",
            sa.Integer,
            sa.ForeignKey("content_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *_ts_columns(),
        sa.UniqueConstraint(
            "profile_id",
            "channel_id",
            name="content_profile_channels_unique_pair",
        ),
    )
    op.create_index(
        "ix_content_profile_channels_channel",
        "content_profile_channels",
        ["channel_id"],
    )

    # ---- host_content_profile_subscriptions -------------------------------
    op.create_table(
        "host_content_profile_subscriptions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "host_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.Integer,
            sa.ForeignKey("content_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *_ts_columns(),
        sa.UniqueConstraint(
            "host_id",
            "profile_id",
            name="host_content_profile_subs_unique_pair",
        ),
    )
    op.create_index(
        "ix_host_content_profile_subs_profile",
        "host_content_profile_subscriptions",
        ["profile_id"],
    )

    # ---- group_content_profile_subscriptions ------------------------------
    op.create_table(
        "group_content_profile_subscriptions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "group_id",
            sa.Integer,
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.Integer,
            sa.ForeignKey("content_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *_ts_columns(),
        sa.UniqueConstraint(
            "group_id",
            "profile_id",
            name="group_content_profile_subs_unique_pair",
        ),
    )
    op.create_index(
        "ix_group_content_profile_subs_profile",
        "group_content_profile_subscriptions",
        ["profile_id"],
    )

    # ---- smart_group_content_profile_subscriptions ------------------------
    op.create_table(
        "smart_group_content_profile_subscriptions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "smart_group_id",
            sa.Integer,
            sa.ForeignKey("smart_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.Integer,
            sa.ForeignKey("content_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *_ts_columns(),
        sa.UniqueConstraint(
            "smart_group_id",
            "profile_id",
            name="smart_group_content_profile_subs_unique_pair",
        ),
    )
    op.create_index(
        "ix_smart_group_content_profile_subs_profile",
        "smart_group_content_profile_subscriptions",
        ["profile_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_smart_group_content_profile_subs_profile",
        table_name="smart_group_content_profile_subscriptions",
    )
    op.drop_table("smart_group_content_profile_subscriptions")

    op.drop_index(
        "ix_group_content_profile_subs_profile",
        table_name="group_content_profile_subscriptions",
    )
    op.drop_table("group_content_profile_subscriptions")

    op.drop_index(
        "ix_host_content_profile_subs_profile",
        table_name="host_content_profile_subscriptions",
    )
    op.drop_table("host_content_profile_subscriptions")

    op.drop_index(
        "ix_content_profile_channels_channel",
        table_name="content_profile_channels",
    )
    op.drop_table("content_profile_channels")

    op.drop_table("content_profiles")

    op.drop_index(
        "ix_content_channel_repos_mirror",
        table_name="content_channel_repos",
    )
    op.drop_index(
        "ux_content_channel_repos_inherit_suite",
        table_name="content_channel_repos",
    )
    op.drop_table("content_channel_repos")

    op.drop_table("content_channels")
