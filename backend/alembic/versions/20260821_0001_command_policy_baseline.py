"""Record the command-policy baseline that initialization has already applied.

Startup initialization installs a baseline of command whitelist entries,
validation rules, and distro mappings, and previously treated a missing row as
never initialized. Deleting a baseline entry through the API therefore only held
until the next restart, when the entry returned as active policy with its shipped
risk and approval configuration, outside request context and without an audit
event.

``command_policy_baseline`` records each baseline item that has been applied, so
initialization can tell a deliberately deleted item from one that was never
created. The record is independent of the policy row it describes: deleting the
policy row leaves the record in place, and the item is not reinstalled.

A database that has already had the shipped baseline applied gets a record for
every item below, so any of those items that is missing today was removed
deliberately and stays removed. A database that has not yet been initialized gets
no records and receives the full baseline on its next initialization run.

The two are told apart by evidence specific to command policy, never by general
application state. A user row is not evidence: startup creates the admin user
immediately before applying the baseline, so a first boot interrupted between
those two steps leaves a user and no policy at all. Recording the baseline as
applied in that state would strip the shipped whitelist and validation rules from
the installation permanently.

The lists below are a frozen snapshot of the baseline as shipped at this revision.
They describe history and must not be extended when a later release adds a
baseline item: a new item has no record in any database, which is what makes it
install everywhere on the next run.
"""

from __future__ import annotations

import json
from typing import Optional, Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "command_policy_baseline"
down_revision: Union[str, None] = "align_groups_id_sequence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SHIPPED_WHITELIST_ENTRIES = (
    "APT Update",
    "APT Upgrade",
    "APT Install Package",
    "APT Remove Package",
    "APT Search",
    "APT Show Package Info",
    "YUM Update",
    "YUM Install Package",
    "YUM Remove Package",
    "YUM Search",
    "Zypper Refresh",
    "Zypper Update",
    "Zypper Install Package",
    "List Installed Packages (dpkg)",
    "List Installed Packages (rpm)",
    "System Information",
    "OS Release Information",
    "Uptime",
    "Current User",
    "Hostname",
    "Disk Free",
    "Memory Free",
    "Process List",
    "List Directory",
    "Print Working Directory",
    "Kernel Version",
    "Date",
    "Read File",
    "Tail File",
    "Head File",
)

SHIPPED_VALIDATION_RULES = (
    "Dangerous File Operations",
    "Format Commands",
    "Network Configuration",
    "Service Management",
    "Sudo Usage",
    "Privilege Escalation Commands",
    "Read Sensitive Secret Files",
    "Read Account Database",
    "Package Manager Consistency",
)

SHIPPED_DISTRO_MAPPINGS = (
    "APT Update::Ubuntu-20.04",
    "APT Update::Ubuntu-22.04",
    "APT Update::Debian-11",
    "APT Upgrade::Ubuntu-20.04",
    "APT Upgrade::Ubuntu-22.04",
    "APT Upgrade::Debian-11",
    "APT Install Package::Ubuntu-20.04",
    "APT Install Package::Ubuntu-22.04",
    "APT Install Package::Debian-11",
    "APT Remove Package::Ubuntu-20.04",
    "APT Remove Package::Ubuntu-22.04",
    "APT Remove Package::Debian-11",
    "APT Search::Ubuntu-20.04",
    "APT Search::Ubuntu-22.04",
    "APT Search::Debian-11",
    "APT Show Package Info::Ubuntu-20.04",
    "APT Show Package Info::Ubuntu-22.04",
    "APT Show Package Info::Debian-11",
    "YUM Update::CentOS-8",
    "YUM Update::RHEL-8",
    "YUM Install Package::CentOS-8",
    "YUM Install Package::RHEL-8",
    "YUM Remove Package::CentOS-8",
    "YUM Remove Package::RHEL-8",
    "YUM Search::CentOS-8",
    "YUM Search::RHEL-8",
    "Zypper Refresh::SUSE-15",
    "Zypper Update::SUSE-15",
    "Zypper Install Package::SUSE-15",
    "List Installed Packages (dpkg)::Ubuntu-20.04",
    "List Installed Packages (dpkg)::Ubuntu-22.04",
    "List Installed Packages (dpkg)::Debian-11",
    "List Installed Packages (rpm)::CentOS-8",
    "List Installed Packages (rpm)::RHEL-8",
    "List Installed Packages (rpm)::SUSE-15",
)


def _audited_item_name(old_value: Optional[str]) -> Optional[str]:
    """Recover the policy item name an audit row recorded as deleted.

    Audit values are stored as text. A command-policy deletion writes a JSON
    object carrying the name and pattern, but the column is free-form, so a value
    that does not parse is treated as the name itself rather than discarded.
    """
    if not old_value:
        return None
    try:
        parsed = json.loads(old_value)
    except (TypeError, ValueError):
        return old_value.strip() or None
    if isinstance(parsed, dict):
        name = parsed.get("name")
        return name if isinstance(name, str) else None
    if isinstance(parsed, str):
        return parsed or None
    return None


def _command_policy_was_initialized(connection) -> bool:
    """Report whether the shipped baseline has already been applied here.

    Only evidence about command policy itself counts:

    * A surviving whitelist entry or validation rule is direct evidence.
    * An audited deletion naming a shipped baseline item is evidence that the
      item existed and was removed on purpose. This is what covers the install
      whose every baseline row was deliberately deleted, which has no surviving
      row to point at.

    Deliberately not evidence: users, or any other general application state. A
    first boot interrupted after the admin user is created but before the
    baseline is applied must come back as "not initialized" so the next boot
    installs the policy it never received.

    An operator who deletes their own entry leaves an audit too, so the audited
    name has to match a shipped baseline item to count. Rows removed outside the
    application leave no audit and cannot be recognised; that install is treated
    as uninitialized and receives the baseline again.
    """
    for query in (
        "SELECT 1 FROM command_whitelist LIMIT 1",
        "SELECT 1 FROM command_validation_rules LIMIT 1",
    ):
        if connection.execute(sa.text(query)).first() is not None:
            return True

    shipped_names = set(SHIPPED_WHITELIST_ENTRIES) | set(SHIPPED_VALIDATION_RULES)
    deletions = connection.execute(
        sa.text(
            "SELECT old_value FROM system_audits "
            "WHERE operation = 'delete' "
            "AND audit_type IN ('command_whitelist', 'validation_rule')"
        )
    ).fetchall()
    for row in deletions:
        if _audited_item_name(row[0]) in shipped_names:
            return True
    return False


def upgrade() -> None:
    op.create_table(
        "command_policy_baseline",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("item_type", sa.String(length=50), nullable=False),
        sa.Column("item_key", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "item_type", "item_key", name="uq_command_policy_baseline_item"
        ),
    )
    op.create_index(
        op.f("ix_command_policy_baseline_id"),
        "command_policy_baseline",
        ["id"],
    )
    op.create_index(
        op.f("ix_command_policy_baseline_item_type"),
        "command_policy_baseline",
        ["item_type"],
    )

    connection = op.get_bind()
    if not _command_policy_was_initialized(connection):
        return

    # These item types are literals rather than imports so this revision stays a
    # fixed snapshot, but they must keep matching the values initialization reads
    # back. The regression tests compare the two.
    rows = []
    for name in SHIPPED_WHITELIST_ENTRIES:
        rows.append({"item_type": "whitelist_entry", "item_key": name})
    for name in SHIPPED_VALIDATION_RULES:
        rows.append({"item_type": "validation_rule", "item_key": name})
    for key in SHIPPED_DISTRO_MAPPINGS:
        rows.append({"item_type": "distro_mapping", "item_key": key})

    connection.execute(
        sa.text(
            "INSERT INTO command_policy_baseline "
            "(item_type, item_key, created_at, updated_at) "
            "VALUES (:item_type, :item_key, NOW(), NOW())"
        ),
        rows,
    )


def downgrade() -> None:
    """Drop the records only.

    No policy row is touched here, but a database downgraded past this revision
    loses the record of what has been applied, so the next initialization on the
    older code restores every missing baseline item.
    """
    op.drop_index(
        op.f("ix_command_policy_baseline_item_type"),
        table_name="command_policy_baseline",
    )
    op.drop_index(
        op.f("ix_command_policy_baseline_id"), table_name="command_policy_baseline"
    )
    op.drop_table("command_policy_baseline")
