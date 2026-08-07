"""PRA-346: operator-facing humanization of internal compliance enums.

The compliance engine records STABLE internal enum strings in ``verdict_reason``
/ ``runner_owner`` / ``runner_status`` — pinned wire-shape for auditor export
scripts and tests. Several of those strings carry implementation history
(ticket/slice names) or schema jargon that must never reach an operator's
screen (e.g. ``deferred_to_pra166``, ``fact_key_not_in_slice_2_schema``).

This module is the single source of truth that:

* maps each internal enum to a product-facing label, and
* classifies an evidence row into a distinguishable, actionable **status** so
  the UI can tell a real failure apart from "facts not collected yet" or
  "Praxis can't evaluate this yet" — states that previously all read as a raw
  ``error``.

It is a LEAF module: it is keyed by the literal enum strings (which are pinned
by tripwire tests in the compliance test suite), so it imports nothing from the
compliance services and can be imported by all of them without cycles. The raw
enums are intentionally kept stable; these labels are ADDED alongside them.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping, Optional

# ---------------------------------------------------------------------------
# Runner family (from the internal runner_owner). Both historical
# ``deferred_to_*`` owners are actually implemented — the label reflects the
# real evaluator family, not the ticket that shipped it.
# ---------------------------------------------------------------------------

_RUNNER_FAMILY_LABELS = {
    "deferred_to_pra165_slice_2": "Package & fact evaluation",
    "deferred_to_pra166": "Host probe (SSH)",
    "unknown": "Unsupported check",
}


def runner_label(runner_owner: Optional[str]) -> str:
    """Product-facing evaluator family for an internal ``runner_owner``."""
    return _RUNNER_FAMILY_LABELS.get(runner_owner or "", "Unsupported check")


# ---------------------------------------------------------------------------
# Runner status (evidence + check reads). ``runner_not_implemented_in_slice_1``
# is a stale check-read constant (the runner ships now) — humanized truthfully.
# ---------------------------------------------------------------------------

_RUNNER_STATUS_LABELS = {
    "runner_executed": "Evaluated",
    "runner_deferred": "Not evaluated",
    # Stale legacy check-read value — the runner is implemented, so present it
    # honestly as evaluable rather than "not implemented".
    "runner_not_implemented_in_slice_1": "Evaluated on scan",
}


def runner_status_label(runner_status: Optional[str]) -> str:
    return _RUNNER_STATUS_LABELS.get(runner_status or "", "Not evaluated")


# ---------------------------------------------------------------------------
# Evidence status classification — splits the single ``error`` verdict into
# distinguishable, actionable product states.
# ---------------------------------------------------------------------------

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_ERROR = "error"
STATUS_COVERAGE_PENDING = "coverage_pending"
STATUS_AWAITING_SCAN = "awaiting_scan"
STATUS_UNSUPPORTED = "unsupported"

_STATUS_LABELS = {
    STATUS_PASS: "Pass",
    STATUS_FAIL: "Fail",
    STATUS_ERROR: "Error",
    STATUS_COVERAGE_PENDING: "Coverage pending",
    STATUS_AWAITING_SCAN: "Awaiting host scan",
    STATUS_UNSUPPORTED: "Unsupported",
}

# "facts simply not collected for this host yet" — actionable: run a scan.
_AWAITING_SCAN_REASONS = frozenset({"no_host_facts_row", "fact_value_null"})
# "Praxis does not collect the fact this check needs yet" — coverage gap, not a
# host problem and not a broken app.
_COVERAGE_PENDING_REASONS = frozenset({"fact_key_not_in_slice_2_schema"})
# defensive/unknown-kind reasons -> unsupported, not a scary generic error.
_UNSUPPORTED_REASON_PREFIXES = (
    "unknown_kind:",
    "unknown_runner_owner:",
    "missing_runner_for_kind:",
    "unsupported_probe_kind:",
)
_UNSUPPORTED_REASONS = frozenset(
    {"runner_owner_deferred_pra166", "unsupported_probe_kind"}
)


def evidence_status(verdict: str, verdict_reason: Optional[str]) -> str:
    """Classify an evidence row into a distinguishable product status.

    ``pass`` / ``fail`` map through unchanged. A ``verdict == 'error'`` row is
    split by its reason so operators can act: ``coverage_pending`` (fact not
    collected by Praxis yet), ``awaiting_scan`` (host not scanned yet),
    ``unsupported`` (unknown/deferred kind), or a genuine ``error``.
    """
    if verdict == STATUS_PASS:
        return STATUS_PASS
    if verdict == STATUS_FAIL:
        return STATUS_FAIL
    reason = verdict_reason or ""
    if reason in _COVERAGE_PENDING_REASONS:
        return STATUS_COVERAGE_PENDING
    if reason in _AWAITING_SCAN_REASONS:
        return STATUS_AWAITING_SCAN
    if reason in _UNSUPPORTED_REASONS or reason.startswith(
        _UNSUPPORTED_REASON_PREFIXES
    ):
        return STATUS_UNSUPPORTED
    return STATUS_ERROR


def status_label(status: str) -> str:
    return _STATUS_LABELS.get(status, "Error")


def status_label_for(verdict: str, verdict_reason: Optional[str]) -> str:
    return status_label(evidence_status(verdict, verdict_reason))


# ---------------------------------------------------------------------------
# Verdict reason -> operator sentence.
# ---------------------------------------------------------------------------

_VERDICT_REASON_LABELS = {
    "no_host_facts_row": "No host facts collected yet — run a scan on this host.",
    "fact_key_not_in_slice_2_schema": "This check needs a host fact Praxis doesn't collect yet.",
    "fact_value_null": "The host fact this check needs has no value yet.",
    "package_not_installed": "Package is not installed.",
    "package_installed": "Package is installed.",
    "installed_version_below_min": "Installed version is below the required minimum.",
    "installed_version_unparseable": "The installed version string could not be read.",
    "runner_owner_deferred_pra166": "Not evaluated on this record.",
    # host-probe reasons
    "file_not_found": "File not found on the host.",
    "file_unreadable": "File exists but could not be read on the host.",
    "sha256_mismatch": "File checksum did not match the expected value.",
    "sha256sum_no_output": "The checksum command returned no output.",
    "permission_denied": "Permission denied while reading on the host.",
    "command_not_found": "Command not found on the host.",
    "exit_code_mismatch": "Command exit code did not match the expected value.",
    "stdout_did_not_contain_substring": "Command output did not contain the expected text.",
    "probe_timeout": "The host probe timed out.",
    "ssh_transport_failure": "Could not connect to the host over SSH.",
    "system_not_found": "Host not found.",
    "invalid_probe_result": "The host probe returned an unexpected result.",
    "unsupported_probe_kind": "This check type isn't supported yet.",
}

# Dynamic reasons (``prefix:internal_suffix``). The suffix is NEVER echoed —
# it can itself be an internal owner/kind string, so we return a generic label.
_DYNAMIC_REASON_LABELS = {
    "unknown_kind:": "This check type isn't supported yet.",
    "unknown_runner_owner:": "This check type isn't supported yet.",
    "missing_runner_for_kind:": "No evaluator is available for this check type.",
    "unsupported_probe_kind:": "This check type isn't supported yet.",
}

# Patterns that mark an internal/leaky string. Used to fail-closed on any reason
# the maps don't cover, so a future internal reason can never reach an operator.
# NOTE: the ticket pattern is ``pra`` + digit (e.g. ``pra166``), NOT a bare
# ``pra`` — the product name "Praxis" legitimately contains "pra".
_INTERNAL_RE = re.compile(
    r"pra\d|slice[ _]?\d|_slice\b|not_in_[a-z0-9_]*_schema|deferred_to",
    re.IGNORECASE,
)


def _looks_internal(value: str) -> bool:
    return bool(_INTERNAL_RE.search(value))


def verdict_reason_label(verdict_reason: Optional[str]) -> Optional[str]:
    """Operator-readable explanation for an internal ``verdict_reason``.

    Returns ``None`` when there is no reason (a plain pass/fail). Known reasons
    map to a sentence; dynamic ``prefix:suffix`` reasons map to a generic
    sentence WITHOUT echoing the (possibly internal) suffix; anything else is
    fail-closed — humanized if it looks safe, otherwise a neutral fallback so
    no internal token ever surfaces.
    """
    if verdict_reason is None or verdict_reason == "":
        return None
    if verdict_reason in _VERDICT_REASON_LABELS:
        return _VERDICT_REASON_LABELS[verdict_reason]
    for prefix, label in _DYNAMIC_REASON_LABELS.items():
        if verdict_reason.startswith(prefix):
            return label
    if _looks_internal(verdict_reason):
        return "Not evaluated (see raw reason in export)."
    return verdict_reason.replace("_", " ").strip().capitalize()


VERDICT_LABELS = {
    STATUS_PASS: "Pass",
    STATUS_FAIL: "Fail",
    STATUS_ERROR: "Error",
}


def verdict_label(verdict: Optional[str]) -> str:
    return VERDICT_LABELS.get(verdict or "", "Error")


# ---------------------------------------------------------------------------
# Fail-closed invariant: NO product-facing label may contain an internal token.
# Runs at import so a leaky label can never ship. (Dynamic-reason suffixes are
# never echoed, so only the static label tables need checking.)
# ---------------------------------------------------------------------------


_LABEL_TABLES = (
    _RUNNER_FAMILY_LABELS,
    _RUNNER_STATUS_LABELS,
    _STATUS_LABELS,
    _VERDICT_REASON_LABELS,
    _DYNAMIC_REASON_LABELS,
    VERDICT_LABELS,
)


def _check_no_leak(tables: Iterable[Mapping[str, str]]) -> None:
    """Raise when any static product-facing label carries an internal token.

    Raised explicitly rather than asserted so the invariant still fails closed
    on an optimized interpreter, where assertions are stripped.
    """
    for table in tables:
        for label in table.values():
            if _looks_internal(label):
                raise RuntimeError(f"leaky compliance label: {label!r}")


_check_no_leak(_LABEL_TABLES)
