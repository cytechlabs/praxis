"""PRA-156 #3e-b: eol_warning → host_eol_approaching+host_eol_reached.

Pins the locked behavior:

  * SUPPORTED_EVENT_TYPES no longer carries ``eol_warning`` — it now
    carries the two locked lifecycle event types.
  * notification_preferences ALL_EVENT_TYPES mirrors the same shape.
  * The Alembic JSON-array rewrite (tested via direct call to the
    migration's helper) replaces ``eol_warning`` with
    ``host_eol_approaching`` while preserving order and deduping
    when both the old and new value appear in the same array.
  * Downgrade reverses BOTH new event types back to ``eol_warning``,
    again with order-preserving dedupe.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from app.api.routes import notification_preferences
from app.services import alert_service

# Load the migration module directly so we can test the helper. Alembic
# migration files don't sit on the importable path, so we walk the file
# in via importlib.
_MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "20260502_0003_pra156_rename_eol_warning_event.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "pra156_eol_event_migration", _MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- supported list


def test_supported_event_types_dropped_eol_warning():
    assert "eol_warning" not in alert_service.SUPPORTED_EVENT_TYPES


def test_supported_event_types_added_lifecycle_pair():
    assert "host_eol_approaching" in alert_service.SUPPORTED_EVENT_TYPES
    assert "host_eol_reached" in alert_service.SUPPORTED_EVENT_TYPES


def test_notification_preferences_all_types_mirrors_lifecycle_pair():
    """The /notification_preferences endpoint validates posted
    disabled_types against ALL_EVENT_TYPES — if the supported list
    drifts from alert_service, valid lifecycle preferences would be
    rejected."""
    assert "eol_warning" not in notification_preferences.ALL_EVENT_TYPES
    assert "host_eol_approaching" in notification_preferences.ALL_EVENT_TYPES
    assert "host_eol_reached" in notification_preferences.ALL_EVENT_TYPES


# ---------------------------------------------------------------- migration helper


def test_rewrite_array_replaces_eol_warning():
    mig = _load_migration()
    raw = '["eol_warning", "host_key_changed"]'
    assert mig._rewrite_array(raw, {"eol_warning": "host_eol_approaching"}) == (
        '["host_eol_approaching", "host_key_changed"]'
    )


def test_rewrite_array_dedupes_when_both_old_and_new_present():
    """LOCKED test: an array carrying BOTH the old and the new value
    must collapse to a single ``host_eol_approaching`` after the
    rewrite. Without dedupe, the operator would see the new event
    twice in their preferences UI."""
    mig = _load_migration()
    raw = '["eol_warning", "host_key_changed", "host_eol_approaching"]'
    out = mig._rewrite_array(raw, {"eol_warning": "host_eol_approaching"})
    # Order is preserved by dict.fromkeys — the duplicate is dropped
    # at its second appearance, so the kept ordering follows where
    # the value FIRST showed up.
    assert out == '["host_eol_approaching", "host_key_changed"]'


def test_rewrite_array_preserves_unrelated_entries():
    mig = _load_migration()
    raw = '["job_completed", "system_unreachable", "credential_change"]'
    out = mig._rewrite_array(raw, {"eol_warning": "host_eol_approaching"})
    assert out == raw  # nothing to rewrite


def test_rewrite_array_handles_empty_array():
    mig = _load_migration()
    assert mig._rewrite_array("[]", {"eol_warning": "host_eol_approaching"}) == "[]"


def test_rewrite_array_handles_null_input():
    mig = _load_migration()
    assert mig._rewrite_array(None, {"eol_warning": "host_eol_approaching"}) is None


def test_rewrite_array_returns_input_for_malformed_json():
    """A pre-existing malformed row shouldn't fail the migration —
    return the input unchanged so the operator can clean it up
    after upgrade."""
    mig = _load_migration()
    bad = "{not even json"
    assert mig._rewrite_array(bad, {"eol_warning": "host_eol_approaching"}) == bad


def test_rewrite_array_returns_input_for_non_list_json():
    mig = _load_migration()
    not_a_list = '{"foo": "bar"}'
    assert (
        mig._rewrite_array(not_a_list, {"eol_warning": "host_eol_approaching"})
        == not_a_list
    )


def test_rewrite_array_passes_through_unhashable_entries():
    """Pre-existing junk rows can contain objects or nested lists
    inside the JSON array. Those entries are unhashable so a naive
    dict.fromkeys dedupe would crash and fail the migration on one
    bad row. The helper must dedupe strings only and pass non-strings
    through in place."""
    mig = _load_migration()
    raw = '["eol_warning", {"x": 1}, "host_key_changed", ["nested"], "eol_warning"]'
    out = mig._rewrite_array(raw, {"eol_warning": "host_eol_approaching"})
    # First eol_warning becomes host_eol_approaching, second copy
    # gets deduped. Object + nested list pass through in place.
    import json as _json

    parsed = _json.loads(out)
    assert parsed == [
        "host_eol_approaching",
        {"x": 1},
        "host_key_changed",
        ["nested"],
    ]


def test_downgrade_mapping_collapses_both_lifecycle_types():
    """Downgrade: both new event types map back to ``eol_warning``,
    with dedupe collapsing to a single entry. Operators who'd
    explicitly added host_eol_reached lose that distinction —
    documented best-effort downgrade."""
    mig = _load_migration()
    raw = '["host_eol_approaching", "host_eol_reached", "host_key_changed"]'
    out = mig._rewrite_array(
        raw,
        {
            "host_eol_approaching": "eol_warning",
            "host_eol_reached": "eol_warning",
        },
    )
    assert out == '["eol_warning", "host_key_changed"]'
