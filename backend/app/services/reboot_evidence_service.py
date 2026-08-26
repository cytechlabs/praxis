"""Authoritative reboot-required evidence collection.

A managed host's ``reboot_required`` inventory fact is a snapshot from
the last inventory sweep. It is not evidence about the state a host is
in *after* a package operation: an update that installs a new kernel
flips the host's real answer, and the stored fact keeps reporting the
pre-update value until the next sweep. Any reboot decision that reads
the stored fact therefore risks declaring "no reboot needed" for a host
that just became one reboot behind.

This module collects the answer directly from the host at the moment
the decision is made, using the indicator each package family treats as
authoritative:

* Debian family: the ``/var/run/reboot-required`` /
  ``/run/reboot-required`` marker files that ``update-notifier-common``
  and the kernel/libc post-install hooks create.
* RPM family: ``needs-restarting -r``, whose exit status is the
  documented answer (``0`` no reboot needed, ``1`` reboot needed).

Every collection produces a :class:`RebootEvidence` record carrying the
observed value, the indicator it came from, when it was collected, and
a structured probe outcome. An outcome other than ``success`` means the
value is not known; callers must treat that as "unknown", never as "no
reboot needed". Only a ``success`` outcome carries a trustworthy
``value``.

The probe is read-only: it inspects marker files or asks
``needs-restarting`` for its verdict. It never mutates the host, never
installs the tooling it looks for, and never reboots anything.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.redaction import redact_text
from ..db.models import Distro, HostFacts, System

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------

# Package families we can collect authoritative evidence for.
FAMILY_DEB = "deb"
FAMILY_RPM = "rpm"
FAMILY_UNKNOWN = "unknown"

# Indicator the value came from. ``none`` means no probe ran, so the
# value is absent by construction rather than by failure.
SOURCE_DEBIAN_MARKER = "debian_reboot_required_marker"
SOURCE_RPM_NEEDS_RESTARTING = "rpm_needs_restarting"
SOURCE_NONE = "none"

# Probe outcomes. ``success`` is the ONLY outcome that carries a
# trustworthy ``value``; every other outcome means unknown.
OUTCOME_SUCCESS = "success"
OUTCOME_UNSUPPORTED = "unsupported"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_TRANSPORT_ERROR = "transport_error"
OUTCOME_MALFORMED_OUTPUT = "malformed_output"
OUTCOME_PROBE_FAILED = "probe_failed"
# The caller decided not to probe because the reboot decision does not
# depend on the answer (``never`` and ``always`` policies).
OUTCOME_NOT_COLLECTED = "not_collected"

CONCLUSIVE_OUTCOMES = frozenset({OUTCOME_SUCCESS})


# Evidence older than this is not accepted as proof about the state a
# host is in now, even when the observation itself succeeded. Bounded
# well under a maintenance window so a queue read hours after the run
# cannot resurrect a stale negative.
MAX_EVIDENCE_AGE_SECONDS = 3600

# Wall-clock budget for one probe. The probe is a file existence test
# or a single ``needs-restarting -r`` call; anything slower is a wedged
# session rather than slow collection.
PROBE_TIMEOUT_SECONDS = 60

# Bound the operator-facing detail so a host that floods stderr cannot
# inflate a JSONB column or a notification body. Detail is redacted before
# it is bounded; see :func:`_bounded`.
MAX_DETAIL_CHARS = 512


# ---------------------------------------------------------------------------
# Probe scripts
# ---------------------------------------------------------------------------

# Both scripts print exactly one ``PRAXIS_REBOOT_PROBE=<token>`` line
# and exit 0 when the probe itself ran. A non-zero exit or a missing
# token means the probe did not produce an answer, which the parser
# turns into an unknown outcome rather than a value.

_DEB_PROBE_SCRIPT = (
    "if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then "
    "echo PRAXIS_REBOOT_PROBE=true; else echo PRAXIS_REBOOT_PROBE=false; fi"
)

# ``needs-restarting`` ships in dnf-utils / yum-utils and is absent on a
# minimal install. Its absence is a supportability gap the operator can
# close, not a negative answer, so it reports ``unsupported``.
#
# ``-r`` reports on the *system* (kernel, core libraries) rather than
# listing services, and answers through its exit status. The status is
# captured and echoed so a non-zero verdict cannot be confused with the
# shell failing to run the tool at all.
_RPM_PROBE_SCRIPT = (
    "if ! command -v needs-restarting >/dev/null 2>&1; then "
    "echo PRAXIS_REBOOT_PROBE=unsupported; exit 0; fi; "
    "needs-restarting -r >/dev/null 2>&1; "
    "echo PRAXIS_REBOOT_PROBE=rc:$?"
)

_TOKEN_RE = re.compile(r"^PRAXIS_REBOOT_PROBE=(\S+)$", re.MULTILINE)

# ``needs-restarting -r`` exit status: documented answers only. Any
# other status is the tool failing, not a verdict.
_NEEDS_RESTARTING_EXIT_MEANING: Dict[int, bool] = {0: False, 1: True}


# ---------------------------------------------------------------------------
# Evidence record
# ---------------------------------------------------------------------------


@dataclass
class RebootEvidence:
    """One authoritative reboot-required observation.

    ``value`` is meaningful only when ``outcome`` is ``success``; it is
    ``None`` for every unknown outcome so a caller that ignores the
    outcome still cannot read a fabricated ``False``.
    """

    value: Optional[bool]
    source: str
    outcome: str
    collected_at: datetime
    family: str = FAMILY_UNKNOWN
    exit_code: Optional[int] = None
    detail: str = ""

    @property
    def is_conclusive(self) -> bool:
        """True when the observation proves the host's current answer."""
        return self.outcome in CONCLUSIVE_OUTCOMES and self.value is not None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for persistence in a JSONB detail column.

        ``collected_at`` is an absolute-UTC ISO 8601 string so a stored
        observation cannot be misread as local time.
        """
        return {
            "value": self.value,
            "source": self.source,
            "outcome": self.outcome,
            "collected_at": _utc_iso(self.collected_at),
            "family": self.family,
            "exit_code": self.exit_code,
            "detail": self.detail,
        }


def _utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Absolute-UTC ISO 8601 rendering, matching the patch lifecycle
    convention of naive-UTC storage with an explicit ``Z`` on the wire."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.isoformat().replace("+00:00", "Z")


def not_collected(
    *, reason: str, now: Optional[datetime] = None, family: str = FAMILY_UNKNOWN
) -> RebootEvidence:
    """Evidence record for a host the caller deliberately did not probe."""
    return RebootEvidence(
        value=None,
        source=SOURCE_NONE,
        outcome=OUTCOME_NOT_COLLECTED,
        collected_at=now or datetime.utcnow(),
        family=family,
        detail=_bounded(reason),
    )


def transport_failure(
    *, reason: Any, now: Optional[datetime] = None, family: str = FAMILY_UNKNOWN
) -> RebootEvidence:
    """Evidence record for a host that could not be reached at all.

    Detail is redacted and bounded like every other operator-facing
    detail, so a raised transport error that embeds a credential or a
    connection URL cannot reach the response it is reported in.
    """
    return RebootEvidence(
        value=None,
        source=source_for_family(family),
        outcome=OUTCOME_TRANSPORT_ERROR,
        collected_at=now or datetime.utcnow(),
        family=family,
        detail=_bounded(reason),
    )


def evidence_from_dict(raw: Any) -> Optional[RebootEvidence]:
    """Rebuild a :class:`RebootEvidence` from a persisted JSONB block.

    Returns ``None`` when the block is absent or does not carry the
    fields a decision depends on, so a truncated or hand-edited row is
    treated as "no evidence" instead of raising.
    """
    if not isinstance(raw, dict):
        return None
    outcome = raw.get("outcome")
    source = raw.get("source")
    if not isinstance(outcome, str) or not isinstance(source, str):
        return None
    collected_at = _parse_iso(raw.get("collected_at"))
    if collected_at is None:
        return None
    value = raw.get("value")
    if value is not None and not isinstance(value, bool):
        return None
    exit_code = raw.get("exit_code")
    if exit_code is not None and (
        isinstance(exit_code, bool) or not isinstance(exit_code, int)
    ):
        exit_code = None
    family = raw.get("family")
    detail = raw.get("detail")
    return RebootEvidence(
        value=value,
        source=source,
        outcome=outcome,
        collected_at=collected_at,
        family=family if isinstance(family, str) else FAMILY_UNKNOWN,
        exit_code=exit_code,
        detail=detail if isinstance(detail, str) else "",
    )


def _parse_iso(raw: Any) -> Optional[datetime]:
    """Parse an absolute-UTC ISO string back to the naive-UTC
    convention the patch lifecycle stores. Returns ``None`` for any
    value that does not parse."""
    if not isinstance(raw, str) or not raw:
        return None
    text = raw[:-1] if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        # Convert through UTC explicitly. ``astimezone()`` with no argument
        # would convert through whatever zone the process happens to run in,
        # which would shift a stored instant by the host's offset and make
        # freshness depend on where the backend is deployed.
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def is_fresh(
    evidence: Optional[RebootEvidence],
    *,
    now: datetime,
    not_before: Optional[datetime] = None,
    max_age_seconds: int = MAX_EVIDENCE_AGE_SECONDS,
) -> bool:
    """Whether ``evidence`` still proves the host's current answer.

    Fresh means all of:

    * the observation succeeded and carries a value;
    * it was collected at or after ``not_before`` (the moment the
      package operation finished), so it describes the post-update
      host rather than the pre-update one; and
    * it is not older than ``max_age_seconds``.

    A collection timestamp in the future is not treated as fresh; a
    clock that disagrees with the server is a reason to re-observe, not
    a reason to trust an unverifiable record.
    """
    if evidence is None or not evidence.is_conclusive:
        return False
    collected_at = evidence.collected_at
    if collected_at > now:
        return False
    if not_before is not None and collected_at < not_before:
        return False
    return (now - collected_at).total_seconds() <= max_age_seconds


# ---------------------------------------------------------------------------
# Family resolution
# ---------------------------------------------------------------------------

# Distro-name substring to package family. Mirrors the distro coverage
# the package service supports so a host Praxis can patch is a host
# Praxis can collect reboot evidence for.
_DISTRO_FAMILY = {
    "ubuntu": FAMILY_DEB,
    "debian": FAMILY_DEB,
    "centos": FAMILY_RPM,
    "rhel": FAMILY_RPM,
    "red hat": FAMILY_RPM,
    "rocky": FAMILY_RPM,
    "alma": FAMILY_RPM,
    "almalinux": FAMILY_RPM,
    "fedora": FAMILY_RPM,
    "oracle": FAMILY_RPM,
}

# Fallback when the distro row is missing or unrecognized: the package
# manager the last inventory sweep observed.
_PACKAGE_MANAGER_FAMILY = {
    "apt": FAMILY_DEB,
    "dpkg": FAMILY_DEB,
    "dnf": FAMILY_RPM,
    "yum": FAMILY_RPM,
    "rpm": FAMILY_RPM,
}


def resolve_family(db: Session, system: System) -> str:
    """Return the package family to probe for ``system``.

    Prefers the system's distro because it is operator-declared and
    stable, and falls back to the collected ``package_manager`` fact
    when the distro is missing or outside the supported set. Returns
    ``unknown`` when neither identifies a family; the caller reports
    that as ``unsupported`` rather than guessing an indicator.
    """
    distro_name = (
        db.query(Distro.name).filter(Distro.id == system.distro_id).scalar()
        if system.distro_id is not None
        else None
    )
    if distro_name:
        lowered = distro_name.lower()
        for needle, family in _DISTRO_FAMILY.items():
            if needle in lowered:
                return family

    package_manager = (
        db.query(HostFacts.package_manager)
        .filter(HostFacts.system_id == system.id)
        .scalar()
    )
    if isinstance(package_manager, str):
        family = _PACKAGE_MANAGER_FAMILY.get(package_manager.strip().lower())
        if family:
            return family
    return FAMILY_UNKNOWN


def probe_script_for_family(family: str) -> Optional[str]:
    """Return the shell probe for ``family``, or ``None`` when the
    family has no authoritative indicator we can read."""
    if family == FAMILY_DEB:
        return _DEB_PROBE_SCRIPT
    if family == FAMILY_RPM:
        return _RPM_PROBE_SCRIPT
    return None


def probe_argv(family: str) -> Optional[List[str]]:
    """Return the argv form of the probe for transports that take one."""
    script = probe_script_for_family(family)
    if script is None:
        return None
    return ["sh", "-c", script]


def source_for_family(family: str) -> str:
    """Return the indicator name an observation for ``family`` comes
    from, or ``none`` when the family has no authoritative indicator."""
    if family == FAMILY_DEB:
        return SOURCE_DEBIAN_MARKER
    if family == FAMILY_RPM:
        return SOURCE_RPM_NEEDS_RESTARTING
    return SOURCE_NONE


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def _bounded(text: Any) -> str:
    """Make one piece of probe output safe to persist and display.

    Evidence detail carries remote stdout/stderr and exception text, so a
    host that echoes a credential, a login banner that prints a token, or a
    transport error that embeds a DSN would otherwise land verbatim in a
    JSONB column, the queue API, the CSV export, and an operator
    notification. Every detail is run through the canonical redaction pass
    first, then bounded, so a secret cannot survive by being long enough to
    be truncated into a different shape.
    """
    if text is None:
        return ""
    value = redact_text(str(text)).strip()
    if len(value) <= MAX_DETAIL_CHARS:
        return value
    return value[: MAX_DETAIL_CHARS - 3] + "..."


def parse_probe_result(
    *,
    family: str,
    exit_code: Optional[int],
    stdout: str,
    stderr: str,
    now: datetime,
) -> RebootEvidence:
    """Turn one completed probe run into an evidence record.

    ``exit_code`` is the exit status of the probe script itself, not of
    ``needs-restarting`` (which the RPM script echoes into its output
    precisely so the two cannot be conflated).

    Only a script exit of 0 carrying a recognized token yields a value.
    A non-zero script exit is ``probe_failed``, a missing or unreadable
    token is ``malformed_output``, and an RPM host without
    ``needs-restarting`` is ``unsupported``.
    """
    source = source_for_family(family)
    if exit_code is None or exit_code != 0:
        return RebootEvidence(
            value=None,
            source=source,
            outcome=OUTCOME_PROBE_FAILED,
            collected_at=now,
            family=family,
            exit_code=exit_code,
            detail=_bounded(stderr or stdout),
        )

    match = _TOKEN_RE.search(stdout or "")
    if match is None:
        return RebootEvidence(
            value=None,
            source=source,
            outcome=OUTCOME_MALFORMED_OUTPUT,
            collected_at=now,
            family=family,
            exit_code=exit_code,
            detail=_bounded(stdout or stderr),
        )

    token = match.group(1)
    if token == "unsupported":
        return RebootEvidence(
            value=None,
            source=source,
            outcome=OUTCOME_UNSUPPORTED,
            collected_at=now,
            family=family,
            exit_code=exit_code,
            detail="needs-restarting is not installed on this host",
        )
    if family == FAMILY_DEB:
        if token in ("true", "false"):
            return RebootEvidence(
                value=token == "true",
                source=source,
                outcome=OUTCOME_SUCCESS,
                collected_at=now,
                family=family,
                exit_code=exit_code,
            )
    elif family == FAMILY_RPM and token.startswith("rc:"):
        raw_rc = token[3:]
        try:
            tool_exit = int(raw_rc)
        except ValueError:
            tool_exit = None
        if tool_exit is not None:
            meaning = _NEEDS_RESTARTING_EXIT_MEANING.get(tool_exit)
            if meaning is not None:
                return RebootEvidence(
                    value=meaning,
                    source=source,
                    outcome=OUTCOME_SUCCESS,
                    collected_at=now,
                    family=family,
                    exit_code=tool_exit,
                )
            # An undocumented status is the tool erroring out. Report
            # the failure and keep the status so an operator can look
            # it up rather than inferring a verdict from it.
            return RebootEvidence(
                value=None,
                source=source,
                outcome=OUTCOME_PROBE_FAILED,
                collected_at=now,
                family=family,
                exit_code=tool_exit,
                detail=_bounded(
                    f"needs-restarting -r exited {tool_exit}; "
                    "only 0 (no reboot needed) and 1 (reboot needed) are answers"
                ),
            )

    return RebootEvidence(
        value=None,
        source=source,
        outcome=OUTCOME_MALFORMED_OUTPUT,
        collected_at=now,
        family=family,
        exit_code=exit_code,
        detail=_bounded(stdout or stderr),
    )


# ---------------------------------------------------------------------------
# Transport-bound collection
# ---------------------------------------------------------------------------

# A probe runner takes the resolved system and the probe argv and
# returns the completed run. Callers inject their own so a probe rides
# whichever transport the surrounding operation already uses, and so
# tests never open a session to a real host.
#
# The returned mapping carries ``exit_code`` (``None`` when the command
# never reported one), ``stdout``, ``stderr``, and an optional
# ``outcome`` of ``timeout`` / ``transport_error`` when the transport
# itself failed rather than the command.
ProbeRunner = Callable[[System, List[str]], Dict[str, Any]]


def collect(
    db: Session,
    system: System,
    *,
    runner: ProbeRunner,
    now: Optional[datetime] = None,
    family: Optional[str] = None,
) -> RebootEvidence:
    """Collect one authoritative observation for ``system``.

    Resolves the package family, runs that family's probe through
    ``runner``, and reports the structured outcome. A host whose family
    has no authoritative indicator is reported ``unsupported`` without
    a round-trip. A runner that raises is reported ``transport_error``:
    an unreachable host produces unknown evidence, never a value.
    """
    current_now = now or datetime.utcnow()
    resolved_family = family or resolve_family(db, system)
    argv = probe_argv(resolved_family)
    if argv is None:
        return RebootEvidence(
            value=None,
            source=SOURCE_NONE,
            outcome=OUTCOME_UNSUPPORTED,
            collected_at=current_now,
            family=resolved_family,
            detail=(
                "no authoritative reboot-required indicator is defined for this "
                "host's package family"
            ),
        )

    try:
        result = runner(system, argv)
    except Exception as exc:  # pylint: disable=broad-except
        # Log the exception category only. Its text can carry remote output
        # or a connection string; the operator-safe form is on the record
        # this returns, which is redacted.
        logger.warning(
            "reboot evidence probe raised for system=%s: %s",
            system.id,
            type(exc).__name__,
        )
        return RebootEvidence(
            value=None,
            source=source_for_family(resolved_family),
            outcome=OUTCOME_TRANSPORT_ERROR,
            collected_at=current_now,
            family=resolved_family,
            detail=_bounded(exc),
        )

    result = result or {}
    transport_outcome = result.get("outcome")
    if transport_outcome in (OUTCOME_TIMEOUT, OUTCOME_TRANSPORT_ERROR):
        return RebootEvidence(
            value=None,
            source=source_for_family(resolved_family),
            outcome=transport_outcome,
            collected_at=current_now,
            family=resolved_family,
            exit_code=result.get("exit_code"),
            detail=_bounded(result.get("stderr") or result.get("detail")),
        )

    return parse_probe_result(
        family=resolved_family,
        exit_code=result.get("exit_code"),
        stdout=result.get("stdout") or "",
        stderr=result.get("stderr") or "",
        now=current_now,
    )


def dispatch_runner(db: Session) -> ProbeRunner:
    """Probe runner for the governed patch path.

    Reuses the patch dispatch transport so the probe crosses the same
    connection, credential, and privilege-escalation path as the
    package command whose effect it is measuring.
    """

    def _run(system: System, argv: List[str]) -> Dict[str, Any]:
        from .patch_execution_dispatch_service import (
            ERROR_CODE_TRANSPORT_ERROR,
            ERROR_CODE_TRANSPORT_UNAVAILABLE,
            default_dispatch,
        )

        result = default_dispatch(db, system, argv)
        if result.error in (
            ERROR_CODE_TRANSPORT_ERROR,
            ERROR_CODE_TRANSPORT_UNAVAILABLE,
        ):
            return {
                "outcome": OUTCOME_TRANSPORT_ERROR,
                "exit_code": None,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    return _run


def ssh_runner(ssh_service: Any) -> ProbeRunner:
    """Probe runner for the direct package-update path.

    Reuses the caller's :class:`SSHService` so the probe inherits the
    connection and ``sudo_method`` handling the update itself used.
    """

    def _run(system: System, argv: List[str]) -> Dict[str, Any]:
        # ``execute_privileged_command`` takes a command line rather
        # than an argv list; the probe body is already a single ``sh -c``
        # argument, so it crosses as one quoted string.
        command = " ".join(shlex.quote(part) for part in argv)
        result = ssh_service.execute_privileged_command(
            system.id, command, timeout=PROBE_TIMEOUT_SECONDS
        )
        result = result or {}
        if result.get("timed_out") or result.get("outcome") == "command_timeout":
            return {
                "outcome": OUTCOME_TIMEOUT,
                "exit_code": result.get("exit_code"),
                "stdout": result.get("stdout") or "",
                "stderr": result.get("stderr") or "",
            }
        if result.get("status") == "failed" and result.get("exit_code") is None:
            return {
                "outcome": OUTCOME_TRANSPORT_ERROR,
                "exit_code": None,
                "stdout": result.get("stdout") or "",
                "stderr": result.get("stderr") or "",
            }
        return {
            "exit_code": result.get("exit_code"),
            "stdout": result.get("stdout") or "",
            "stderr": result.get("stderr") or "",
        }

    return _run


def collect_over_ssh(
    db: Session,
    system: System,
    *,
    ssh_service: Any,
    now: Optional[datetime] = None,
) -> RebootEvidence:
    """Convenience wrapper for callers that already hold an SSHService."""
    return collect(db, system, runner=ssh_runner(ssh_service), now=now)
