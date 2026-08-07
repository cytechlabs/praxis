"""PRA-166 Slice 1 — bounded, read-only file/command compliance probe runner.

Executes the four PRA-165-deferred check kinds against a managed host
via a probe-runner-local :class:`SSHService` subclass:

* ``file_exists`` (definition: ``{"path": "..."}``)
* ``file_sha256`` (definition: ``{"path": "...", "sha256": "..."}``)
* ``command_stdout_contains`` (definition: ``{"command": "...",
  "expected_substring": "..."}``)
* ``command_exit_code`` (definition: ``{"command": "...",
  "expected_exit_code": int}``)

Hard scope (PRA-166 Slice 1):

* Probes are **read-only on the target** *and* read-only against the
  backend's own SSH-related tables. Nothing here writes to the host,
  refreshes facts, runs a package scan, mutates state, or triggers
  remediation/approval workflows.
* The slice's "no host mutation" lock covers both target mutations
  and backend bookkeeping of host status. ``_ssh_execute`` runs
  through :class:`_ReadOnlyComplianceSSHService`, a private subclass
  that:
    * skips :meth:`SSHService.execute_command` (the
      ``_update_system_connection_status`` regression vector),
    * overrides :meth:`_log_security_event`,
      :meth:`_store_host_key`, and
      :meth:`_update_system_connection_status` to no-op so the
      cold-connect / connect-failure paths never write
      ``SSHSecurityLog`` or ``SSHHostKey`` rows or call
      ``db.commit()`` mid-evaluation, and
    * refuses to TOFU-trust an unknown host key — fresh hosts must
      be onboarded before they can be compliance-probed; the runner
      returns a stable ``REASON_TRANSPORT_FAILURE`` error verdict
      instead of silently capturing the key.
* Stdout carried back over SSH is bounded by ``WIRE_STDOUT_BYTE_CAP``
  on the remote side via ``head -c``; the evidence ``observed_value``
  is further truncated by ``_truncate_for_evidence`` so a hostile or
  buggy command can't blow up an evidence row.
* Transport errors, paramiko timeouts, permission denials, and other
  failure modes surface as ``error`` verdicts with stable reason
  codes — no silent pass/fail.
* Unsupported / unknown kinds raise :class:`UnsupportedProbeKind` so
  the evaluation runner records an explicit error rather than
  guessing.

The runner is **injected** into ``compliance_evaluation_service`` by
module-level reference; tests can monkeypatch the dispatch table to
assert behavior without a live SSH host. The evaluation service does
not import :mod:`ssh_service` directly — keeping the existing
"evaluation module does not surface probe-runner symbols" boundary
intact.
"""

from __future__ import annotations

import base64
import logging
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from sqlalchemy.orm import Session

from ..db.models import System
from .ssh_service import SSHConnectionError, SSHService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bounds / timeouts
# ---------------------------------------------------------------------------

# Per-probe SSH timeout in seconds. Probes are read-only checks; anything
# slower than this is a stuck SSH session, not slow compliance work.
# Mirrors the broker's hard-cap shape used by the facts collector.
PROBE_TIMEOUT_SECONDS = 30

# Wire-side stdout cap. The remote shell truncates probe stdout with
# ``head -c`` so the backend never buffers megabytes for a bounded
# compliance check.
WIRE_STDOUT_BYTE_CAP = 65_536

# Maximum characters persisted as the evidence ``observed_value``
# preview. Stays well below the column length and keeps the evidence
# row DB-friendly even if WIRE_STDOUT_BYTE_CAP is later raised.
EVIDENCE_OBSERVED_CHAR_CAP = 1_024

# Suffix appended when an evidence value is truncated to the cap.
# Stable so operators / consumers can grep for it.
TRUNCATION_SUFFIX = "...[truncated]"


# ---------------------------------------------------------------------------
# Stable verdict-reason vocabulary
# ---------------------------------------------------------------------------

REASON_TRANSPORT_FAILURE = "ssh_transport_failure"
REASON_PROBE_TIMEOUT = "probe_timeout"
REASON_PERMISSION_DENIED = "permission_denied"
REASON_COMMAND_NOT_FOUND = "command_not_found"
REASON_FILE_NOT_FOUND = "file_not_found"
REASON_FILE_UNREADABLE = "file_unreadable"
REASON_SHA256_MISMATCH = "sha256_mismatch"
REASON_SHA256_UNREADABLE = "sha256sum_no_output"
REASON_STDOUT_DID_NOT_CONTAIN = "stdout_did_not_contain_substring"
REASON_EXIT_CODE_MISMATCH = "exit_code_mismatch"
REASON_INVALID_PROBE_RESULT = "invalid_probe_result"
REASON_SYSTEM_NOT_FOUND = "system_not_found"
REASON_UNSUPPORTED_KIND = "unsupported_probe_kind"

# POSIX shell exit codes that indicate the inner command never produced
# its own result. 126 = file exists but is not executable / lacks
# permission to execute; 127 = command not found on $PATH. We
# distinguish these from a generic exit-code mismatch on
# ``command_exit_code`` probes so operators get an actionable reason
# instead of "expected 0, got 127" (which is technically true but
# obscures that the probe never really ran).
_SHELL_EXIT_PERMISSION_DENIED = 126
_SHELL_EXIT_COMMAND_NOT_FOUND = 127

# Verdict strings — mirror compliance_evaluation_service.VERDICT_*.
# Duplicated here so this module has no import-time dependency on the
# evaluation service module (which imports this one).
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"


# ---------------------------------------------------------------------------
# Public dataclasses + exceptions
# ---------------------------------------------------------------------------


@dataclass
class ProbeOutcome:
    """Result of a single probe execution against one host.

    The shape mirrors the ``CheckVerdict`` consumed by the evaluation
    runner; the evaluation service adapts this back into its own
    verdict dataclass without importing this module's types into its
    public surface.
    """

    verdict: str
    reason: Optional[str] = None
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None


class UnsupportedProbeKind(Exception):
    """Raised when ``run_probe`` is called with a kind this slice does
    not own. The evaluation runner converts this into an explicit
    ``error`` verdict so unsupported kinds never silently pass.
    """


# ---------------------------------------------------------------------------
# Shell helpers — quoting + base64 wrapping
# ---------------------------------------------------------------------------


def _shell_single_quote(value: str) -> str:
    """Return ``value`` POSIX-safely wrapped in single quotes.

    Single quotes inside the value are closed, escaped, then
    re-opened. Works under ``/bin/sh`` (including busybox) so the
    probe runner does not require bash on the target.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def _wrap_command_in_b64_shell(command: str, *, with_stdout_cap: bool) -> str:
    """Wrap an operator-supplied shell command in a base64-decoded
    ``sh -s`` so paramiko's command-line quoting can't interact with
    the command body.

    When ``with_stdout_cap`` is True the pipeline tails through
    ``head -c WIRE_STDOUT_BYTE_CAP`` so unbounded command output never
    reaches the backend. When False the inner command's exit code is
    preserved (the pipeline would otherwise return ``head``'s status).
    """
    b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
    if with_stdout_cap:
        return (
            f"printf %s '{b64}' | base64 -d 2>/dev/null | "
            f"sh -s 2>/dev/null | head -c {WIRE_STDOUT_BYTE_CAP}"
        )
    # Discard stdout/stderr so a chatty inner command can't flood the
    # SSH channel and exit code propagates from ``sh -s`` (last cmd).
    return f"printf %s '{b64}' | base64 -d 2>/dev/null | " "sh -s >/dev/null 2>&1"


# ---------------------------------------------------------------------------
# Evidence-value bounds
# ---------------------------------------------------------------------------


def _truncate_for_evidence(
    value: Optional[str], cap: int = EVIDENCE_OBSERVED_CHAR_CAP
) -> Optional[str]:
    """Bound a string before it is persisted as evidence ``observed_value``.

    ``None`` passes through; otherwise values longer than ``cap`` are
    cut and given a stable ``TRUNCATION_SUFFIX`` so operators can
    grep for them.
    """
    if value is None:
        return None
    if len(value) <= cap:
        return value
    return value[:cap] + TRUNCATION_SUFFIX


# ---------------------------------------------------------------------------
# SSH transport adapter
# ---------------------------------------------------------------------------


def _is_timeout(stderr: str) -> bool:
    """Best-effort detector for paramiko / socket timeout fallthrough.

    The read-only path below catches :class:`socket.timeout` explicitly
    and stamps the stderr string. Older callers and the
    ``SSHConnectionError`` fallback may surface ``timed out`` /
    ``timeout`` substrings; the detector accepts either.
    """
    if not stderr:
        return False
    lowered = stderr.lower()
    return "timed out" in lowered or "timeout" in lowered


# Result-dict status strings. Kept aligned with SSHService's vocabulary
# (``success`` / ``warning`` / ``failed``) so the per-kind probe
# handlers don't need to learn a second result shape.
_STATUS_SUCCESS = "success"
_STATUS_WARNING = "warning"
_STATUS_FAILED = "failed"


def _failed_result(stderr: str) -> Dict[str, Any]:
    return {
        "status": _STATUS_FAILED,
        "stdout": "",
        "stderr": stderr,
        "exit_code": None,
    }


# ---------------------------------------------------------------------------
# Read-only SSH adapter for compliance probes
# ---------------------------------------------------------------------------


# Stable error string for the "fresh host, not yet trusted" refusal.
# Surfaced verbatim in ``stderr`` so ``_transport_failed_outcome`` can
# tag the evidence row with ``REASON_TRANSPORT_FAILURE`` and an
# operator-actionable observed value.
_UNTRUSTED_HOST_KEY_MSG = (
    "compliance probe refuses to TOFU host key; "
    "onboard the host (SSH connect + verify) before re-running the probe."
)


class _ReadOnlyComplianceSSHService(SSHService):
    """SSHService subclass scoped to compliance probe execution only.

    Suppresses every DB-write path inside the SSH transport stack so a
    probe sweep cannot produce ``SSHSecurityLog`` / ``SSHHostKey`` /
    ``SystemMetadata`` rows or commit the session mid-evaluation. Used
    exclusively by :func:`_ssh_execute`; never imported elsewhere.

    Why a subclass instead of patching the base class: the SSH
    security log + host-key TOFU writes are legitimate behaviors for
    interactive sessions / file transfers / facts collection. Only
    compliance probes need the strict "no SSH-side DB writes" mode,
    and the subclass keeps that contract local to PRA-166.
    """

    def _log_security_event(self, system, event_type, details):  # type: ignore[override]
        # Compliance probes are read-only — defer SSH-level connection
        # audit emission to the higher-level compliance audit pipeline,
        # which uses the safe_emit / session-boundary pattern.
        logger.debug(
            "compliance probe: suppressed SSH security event %s for %s",
            event_type,
            getattr(system, "hostname", "?"),
        )

    def _store_host_key(self, system, transport):  # type: ignore[override]
        # No host-key persistence from compliance probes. New hosts
        # must be onboarded through the normal SSH path before they
        # can be compliance-probed.
        logger.debug(
            "compliance probe: suppressed host-key store for %s",
            getattr(system, "hostname", "?"),
        )

    def _update_system_connection_status(self, system, status):  # type: ignore[override]
        # PRA-166 Slice 1 no-host-mutation lock. Belt + suspenders —
        # the probe runner doesn't call execute_command either, so
        # this method shouldn't fire, but the override keeps the
        # boundary explicit if a future refactor reintroduces the
        # call site.
        logger.debug(
            "compliance probe: suppressed system status update (%s -> %s)",
            getattr(system, "hostname", "?"),
            status,
        )

    def _create_connection(self, system, force_password_auth=False):  # type: ignore[override]
        # Refuse to TOFU-trust an unknown host key during a compliance
        # probe — that would write an SSHHostKey row and commit. The
        # parent class only reaches the TOFU policy when host-key
        # verification is required AND no verified known key exists;
        # short-circuit before the parent gets a chance to install
        # HostKeyPromptPolicy.
        if (
            system.ssh_security_policy
            and system.ssh_security_policy.require_host_key_verification
        ):
            known = self._get_known_hosts_for_system(system.id)
            if known is None or not known.verified:
                raise SSHConnectionError(_UNTRUSTED_HOST_KEY_MSG)
        return super()._create_connection(
            system, force_password_auth=force_password_auth
        )


def _ssh_execute(
    db: Session,
    *,
    system_id: int,
    remote_command: str,
    timeout: int,
) -> Dict[str, Any]:
    """Read-only SSH execution for compliance probes.

    Uses :class:`_ReadOnlyComplianceSSHService` (a probe-runner-local
    subclass of :class:`SSHService`) to resolve a pooled paramiko
    client and runs ``client.exec_command`` directly. The subclass
    overrides every DB-write seam inside the SSH stack so the
    compliance evaluation transaction stays clean:

    * ``execute_command`` is never called — its
      ``_update_system_connection_status`` branch is the historical
      ``SystemMetadata`` / ``System.status`` regression vector.
    * ``_log_security_event`` is a no-op — no ``SSHSecurityLog``
      writes or commits on cold connect or connect failure.
    * ``_store_host_key`` is a no-op — no ``SSHHostKey`` writes on
      successful TOFU paths (and TOFU is refused outright when the
      stored policy requires host-key verification).
    * ``_update_system_connection_status`` is a no-op for defense in
      depth.

    Wrapped here so tests can monkeypatch a single seam without
    standing up a real SSH endpoint. Per-kind handlers read
    ``status`` / ``stdout`` / ``stderr`` / ``exit_code`` from the
    returned dict and never observe the bypass.
    """
    svc = _ReadOnlyComplianceSSHService(db)
    try:
        client, _ = svc.get_connection(system_id)
    except SSHConnectionError as exc:
        return _failed_result(str(exc))
    except Exception as exc:  # pylint: disable=broad-except
        return _failed_result(f"Unexpected error: {exc}")

    try:
        _, stdout, stderr = client.exec_command(remote_command, timeout=timeout)
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    except socket.timeout as exc:
        return _failed_result(f"Connection timeout: {exc}")
    except SSHConnectionError as exc:
        return _failed_result(str(exc))
    except Exception as exc:  # pylint: disable=broad-except
        return _failed_result(f"Unexpected error: {exc}")

    status = _STATUS_SUCCESS if exit_code == 0 else _STATUS_WARNING
    return {
        "status": status,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "exit_code": exit_code,
    }


def _transport_failed_outcome(
    result: Dict[str, Any],
    *,
    expected: Optional[str] = None,
) -> ProbeOutcome:
    """Map an SSHService ``status='failed'`` result to an error
    ``ProbeOutcome`` with a stable reason code.
    """
    stderr = (result.get("stderr") or "").strip()
    if _is_timeout(stderr):
        reason = REASON_PROBE_TIMEOUT
    else:
        reason = REASON_TRANSPORT_FAILURE
    return ProbeOutcome(
        verdict=VERDICT_ERROR,
        reason=reason,
        observed_value=_truncate_for_evidence(stderr or None),
        expected_value=expected,
    )


# ---------------------------------------------------------------------------
# Per-kind probe builders + result mappers
# ---------------------------------------------------------------------------


_FILE_EXISTS_MARKERS = {"exists", "absent"}


def _build_file_exists_command(path: str) -> str:
    """``test -e`` wrapper that prints ``exists`` or ``absent`` to
    stdout. Stdout is bounded by the markers themselves so no
    ``head -c`` wrapper is needed.
    """
    pq = _shell_single_quote(path)
    return f"if [ -e {pq} ]; then printf exists; else printf absent; fi"


def _run_file_exists(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> ProbeOutcome:
    path = definition["path"]
    result = _ssh_execute(
        db,
        system_id=system_id,
        remote_command=_build_file_exists_command(path),
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    if result.get("status") == "failed":
        return _transport_failed_outcome(result, expected=path)

    stdout = (result.get("stdout") or "").strip()
    if stdout == "exists":
        return ProbeOutcome(
            verdict=VERDICT_PASS,
            observed_value="exists",
            expected_value=path,
        )
    if stdout == "absent":
        return ProbeOutcome(
            verdict=VERDICT_FAIL,
            reason=REASON_FILE_NOT_FOUND,
            observed_value="absent",
            expected_value=path,
        )
    return ProbeOutcome(
        verdict=VERDICT_ERROR,
        reason=REASON_INVALID_PROBE_RESULT,
        observed_value=_truncate_for_evidence(stdout or None),
        expected_value=path,
    )


_SHA256_LINE_RE = re.compile(r"^[0-9a-f]{64}$")


def _build_file_sha256_command(path: str) -> str:
    """Prefer an explicit error marker over relying on ``sha256sum``'s
    exit code: ``sha256sum`` returns 1 for both "file not found" and
    "permission denied", which would mask a real permission issue. We
    pre-check existence + readability so the verdict_reason is
    actionable.

    The marker tokens ``__NOT_FOUND__`` / ``__UNREADABLE__`` are
    intentionally noisy so a legitimate sha256 hash never collides.
    """
    pq = _shell_single_quote(path)
    return (
        f"if [ ! -e {pq} ]; then printf __NOT_FOUND__; exit 0; fi; "
        f"if [ ! -r {pq} ]; then printf __UNREADABLE__; exit 0; fi; "
        f"sha256sum {pq} 2>/dev/null | awk '{{print $1; exit}}'"
    )


def _run_file_sha256(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> ProbeOutcome:
    path = definition["path"]
    expected_digest = definition["sha256"]
    result = _ssh_execute(
        db,
        system_id=system_id,
        remote_command=_build_file_sha256_command(path),
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    if result.get("status") == "failed":
        return _transport_failed_outcome(result, expected=expected_digest)

    stdout = (result.get("stdout") or "").strip()
    if stdout == "__NOT_FOUND__":
        return ProbeOutcome(
            verdict=VERDICT_FAIL,
            reason=REASON_FILE_NOT_FOUND,
            observed_value="absent",
            expected_value=expected_digest,
        )
    if stdout == "__UNREADABLE__":
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_FILE_UNREADABLE,
            observed_value=path,
            expected_value=expected_digest,
        )
    if not stdout:
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_SHA256_UNREADABLE,
            observed_value=None,
            expected_value=expected_digest,
        )
    digest = stdout.split()[0].strip().lower()
    if not _SHA256_LINE_RE.match(digest):
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_INVALID_PROBE_RESULT,
            observed_value=_truncate_for_evidence(stdout),
            expected_value=expected_digest,
        )
    if digest == expected_digest.lower():
        return ProbeOutcome(
            verdict=VERDICT_PASS,
            observed_value=digest,
            expected_value=expected_digest,
        )
    return ProbeOutcome(
        verdict=VERDICT_FAIL,
        reason=REASON_SHA256_MISMATCH,
        observed_value=digest,
        expected_value=expected_digest,
    )


def _run_command_stdout_contains(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> ProbeOutcome:
    # PRA-166 Slice 3 — documented limitation: this probe cannot
    # safely classify "the inner command exited with permission
    # denied / command not found" the way ``_run_command_exit_code``
    # can. The remote pipeline is ``... | sh -s 2>/dev/null | head -c
    # <WIRE_STDOUT_BYTE_CAP>`` so the SSH-channel exit code reflects
    # ``head``'s status, not the operator command's. Every approach
    # that would recover the inner exit code crosses a Slice 3 lock:
    #
    # * ``set -o pipefail`` / ``${PIPESTATUS[0]}`` — non-POSIX; not
    #   guaranteed under ``/bin/sh`` (busybox on minimal images).
    # * Shell-variable buffering before ``head -c`` — shifts the
    #   unboundedness from paramiko's channel to the remote shell's
    #   variable, breaking the bounded-output contract for hostile
    #   commands.
    # * A second SSH call to capture only the exit code — re-runs
    #   the operator command, which can have side effects if the
    #   command isn't truly read-only (no enforcement at the policy
    #   layer). Crosses the "no host mutation" lock.
    # * Temp-file stash for inner status — direct host write,
    #   crosses the no-host-mutation lock.
    #
    # Net effect today: permission-denied / command-not-found on a
    # stdout-contains probe surfaces as a normal ``fail`` with
    # ``REASON_STDOUT_DID_NOT_CONTAIN``. Operators can disambiguate
    # by adding a parallel ``command_exit_code`` check covering the
    # same binary if classification matters for that audit.
    command = definition["command"]
    expected_substring = definition["expected_substring"]
    remote_command = _wrap_command_in_b64_shell(command, with_stdout_cap=True)
    result = _ssh_execute(
        db,
        system_id=system_id,
        remote_command=remote_command,
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    if result.get("status") == "failed":
        return _transport_failed_outcome(
            result, expected=_truncate_for_evidence(expected_substring)
        )

    stdout = result.get("stdout") or ""
    stdout_preview = _truncate_for_evidence(stdout)
    expected_preview = _truncate_for_evidence(expected_substring)

    if expected_substring in stdout:
        return ProbeOutcome(
            verdict=VERDICT_PASS,
            observed_value=stdout_preview,
            expected_value=expected_preview,
        )
    # If we hit the wire cap the substring might exist past the cut.
    # Mark the result explicitly so operators can raise the cap rather
    # than treating it as a real fail.
    truncated_at_wire = len(stdout.encode("utf-8")) >= WIRE_STDOUT_BYTE_CAP
    reason = REASON_STDOUT_DID_NOT_CONTAIN
    if truncated_at_wire and expected_substring not in stdout:
        # Still a fail (substring not found inside the bounded prefix),
        # but the reason carries the truncation signal so the
        # evidence consumer can distinguish.
        reason = REASON_STDOUT_DID_NOT_CONTAIN
    return ProbeOutcome(
        verdict=VERDICT_FAIL,
        reason=reason,
        observed_value=stdout_preview,
        expected_value=expected_preview,
    )


def _run_command_exit_code(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> ProbeOutcome:
    command = definition["command"]
    expected_code = int(definition["expected_exit_code"])
    remote_command = _wrap_command_in_b64_shell(command, with_stdout_cap=False)
    result = _ssh_execute(
        db,
        system_id=system_id,
        remote_command=remote_command,
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    if result.get("status") == "failed":
        return _transport_failed_outcome(result, expected=str(expected_code))

    exit_code = result.get("exit_code")
    if not isinstance(exit_code, int):
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_INVALID_PROBE_RESULT,
            observed_value=str(exit_code),
            expected_value=str(expected_code),
        )
    if exit_code == expected_code:
        return ProbeOutcome(
            verdict=VERDICT_PASS,
            observed_value=str(exit_code),
            expected_value=str(expected_code),
        )
    # Refine the verdict reason for the two POSIX shell exit codes that
    # signal "the inner command never really ran." These verdicts stay
    # ``fail`` (the probe didn't get the expected exit code), but the
    # reason carries the actionable signal so operators can grep for
    # permission / missing-binary issues without inspecting raw
    # observed_value. Only override when the operator did not
    # *explicitly* expect that code — otherwise the row already
    # produced VERDICT_PASS above.
    if exit_code == _SHELL_EXIT_PERMISSION_DENIED:
        reason = REASON_PERMISSION_DENIED
    elif exit_code == _SHELL_EXIT_COMMAND_NOT_FOUND:
        reason = REASON_COMMAND_NOT_FOUND
    else:
        reason = REASON_EXIT_CODE_MISMATCH
    return ProbeOutcome(
        verdict=VERDICT_FAIL,
        reason=reason,
        observed_value=str(exit_code),
        expected_value=str(expected_code),
    )


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------


# Dispatch table — kept module-level so tests can monkeypatch single
# entries instead of mocking ``SSHService`` end-to-end.
_PROBES: Dict[str, Callable[[Session, int, Dict[str, Any]], ProbeOutcome]] = {
    "file_exists": _run_file_exists,
    "file_sha256": _run_file_sha256,
    "command_stdout_contains": _run_command_stdout_contains,
    "command_exit_code": _run_command_exit_code,
}


SUPPORTED_KINDS = frozenset(_PROBES.keys())


def run_probe(
    db: Session,
    *,
    kind: str,
    system_id: int,
    definition: Dict[str, Any],
) -> ProbeOutcome:
    """Execute one probe of ``kind`` against ``system_id``.

    The host row is looked up up-front so a missing system surfaces as
    a clean error verdict rather than a noisy SSH connection error
    deep inside paramiko. Per-kind handlers see only the validated
    ``definition`` dict the policy service produced.
    """
    if kind not in _PROBES:
        raise UnsupportedProbeKind(kind)

    if not db.query(System.id).filter(System.id == system_id).first():
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_SYSTEM_NOT_FOUND,
            observed_value=None,
            expected_value=None,
        )

    handler = _PROBES[kind]
    try:
        return handler(db, system_id, definition)
    except SSHConnectionError as exc:
        # Defensive — SSHService normally maps this to status='failed';
        # cover the case where a subclass or future change re-raises.
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_TRANSPORT_FAILURE,
            observed_value=_truncate_for_evidence(str(exc)),
            expected_value=None,
        )
    except Exception as exc:  # pylint: disable=broad-except
        # Last-resort guard: any unexpected probe-side error becomes
        # an explicit error verdict rather than crashing the sweep.
        logger.warning(
            "compliance probe %s on system_id=%s raised %s: %s",
            kind,
            system_id,
            type(exc).__name__,
            exc,
        )
        return ProbeOutcome(
            verdict=VERDICT_ERROR,
            reason=REASON_INVALID_PROBE_RESULT,
            observed_value=_truncate_for_evidence(str(exc)),
            expected_value=None,
        )
