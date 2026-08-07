"""PRA-359: host_facts SSH-config + kernel-sysctl scalar columns.

Adds five nullable string columns so the CIS starter-pack SSH/kernel checks can
produce real pass/fail evidence once facts are collected, instead of the
PRA-346 ``coverage_pending`` state:

- ``ssh_permit_root_login`` — effective sshd ``PermitRootLogin``
- ``ssh_password_authentication`` — effective sshd ``PasswordAuthentication``
- ``sysctl_kernel_randomize_va_space`` — ``kernel.randomize_va_space``
- ``sysctl_net_ipv4_ip_forward`` — ``net.ipv4.ip_forward``
- ``sysctl_net_ipv4_conf_all_rp_filter`` — ``net.ipv4.conf.all.rp_filter``

Strictly additive + nullable, so the FactsService schema_version is NOT bumped
(nullable additive facts are backward compatible per the PRA-155 contract) and
existing rows keep working with the new columns NULL.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra359_host_facts_ssh_sysctl"
down_revision: Union[str, None] = "pra358_package_report_kinds"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (
    "ssh_permit_root_login",
    "ssh_password_authentication",
    "sysctl_kernel_randomize_va_space",
    "sysctl_net_ipv4_ip_forward",
    "sysctl_net_ipv4_conf_all_rp_filter",
)


def upgrade() -> None:
    for name in _COLUMNS:
        op.add_column(
            "host_facts",
            sa.Column(name, sa.String(length=64), nullable=True),
        )


def downgrade() -> None:
    for name in reversed(_COLUMNS):
        op.drop_column("host_facts", name)
