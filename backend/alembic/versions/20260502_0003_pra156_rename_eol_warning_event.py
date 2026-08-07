"""PRA-156 slice #3e-b: replace eol_warning with host_eol_approaching.

The vestigial ``eol_warning`` slot has lived in the supported event
list since PRA-43 but never had an emitter. PRA-156 splits it into
two real events fired by the lifecycle emitter (#3e-c):

  * ``host_eol_approaching`` — once per (system, threshold) for the
    90/30/7-day buckets.
  * ``host_eol_reached``     — once per (system, effective_eol_date)
    on the day-zero boundary.

This migration rewrites two JSON-array columns so any operator who
already subscribed to the dead ``eol_warning`` slot keeps receiving
something useful:

  * ``alert_configs.events`` — controls external delivery.
  * ``notification_preferences.disabled_types`` — per-user opt-outs.

The rewrite replaces ``eol_warning`` with ``host_eol_approaching``
(the more frequent of the two new events — opting in here is the
"I want to know about EOL pressure" intent). Operators who want
``host_eol_reached`` add it explicitly. The replacement is
order-preserving and dedupes, so an array that already contains
both ``eol_warning`` and ``host_eol_approaching`` collapses to a
single ``host_eol_approaching`` rather than a duplicate.

Downgrade is a clean reverse: replace each ``host_eol_approaching``
or ``host_eol_reached`` with ``eol_warning``, then dedupe. Operators
who explicitly added ``host_eol_reached`` separately lose that
distinction on downgrade — it merges back into the single
``eol_warning`` slot. Acceptable given the pre-PRA-156 schema
treated lifecycle as one undifferentiated event.
"""

from __future__ import annotations

import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra156_rename_eol_warning_event"
down_revision: Union[str, None] = "pra156_distro_lifecycle_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _rewrite_array(raw: str | None, mapping: dict[str, str]) -> str | None:
    """Apply ``mapping`` to every element of a JSON array column,
    deduping while preserving order. Returns the new JSON string, or
    the original input if it isn't a parseable JSON list (defensive —
    a pre-existing malformed row shouldn't fail the migration).
    """
    if not raw:
        return raw
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return raw
    if not isinstance(parsed, list):
        return raw
    rewritten = [
        mapping.get(item, item) if isinstance(item, str) else item for item in parsed
    ]
    # Order-preserving dedupe across STRING entries only; an array
    # carrying BOTH ``eol_warning`` AND ``host_eol_approaching``
    # collapses to one entry. Non-string entries (objects, nested
    # lists from a malformed pre-existing row) are unhashable, so we
    # can't put them in a set — pass them through in place rather
    # than failing the whole migration on one odd row.
    seen: set[str] = set()
    deduped: list = []
    for item in rewritten:
        if isinstance(item, str):
            if item in seen:
                continue
            seen.add(item)
        deduped.append(item)
    return json.dumps(deduped)


def _apply_mapping(table: str, column: str, mapping: dict[str, str]) -> None:
    """Iterate every row of ``table.column`` and rewrite the JSON
    array in place using ``mapping``. Table/column names are
    hard-coded by the upgrade/downgrade entrypoints — never operator
    input — so the f-string is safe from SQL injection here."""
    bind = op.get_bind()
    rows = bind.execute(sa.text(f"SELECT id, {column} FROM {table}")).fetchall()
    for row_id, raw in rows:
        new_value = _rewrite_array(raw, mapping)
        if new_value != raw:
            bind.execute(
                sa.text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),
                {"v": new_value, "id": row_id},
            )


def upgrade() -> None:
    mapping = {"eol_warning": "host_eol_approaching"}
    _apply_mapping("alert_configs", "events", mapping)
    _apply_mapping("notification_preferences", "disabled_types", mapping)


def downgrade() -> None:
    mapping = {
        "host_eol_approaching": "eol_warning",
        "host_eol_reached": "eol_warning",
    }
    _apply_mapping("alert_configs", "events", mapping)
    _apply_mapping("notification_preferences", "disabled_types", mapping)
