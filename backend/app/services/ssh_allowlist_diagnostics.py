"""sshd account allow-list diagnostics (PRA-234).

The Access Broker deploys the Vault CA, installs the AuthorizedPrincipalsCommand
hook, and self-tests cert auth *as the bootstrap login* (e.g. ``praxis``). None
of that notices native sshd account allow-lists — ``AllowUsers`` /
``AllowGroups`` / ``DenyUsers`` / ``DenyGroups``. On a hardened host with, say,
``AllowUsers praxis``, enrollment and the bootstrap self-test both pass, yet a
later Connect for a provisioned login such as ``operator`` is rejected by sshd
at the allow-list gate *before* the CA cert is ever evaluated. paramiko only
sees a generic ``Authentication (publickey) failed``.

This module turns that opaque failure into a first-class, honest diagnostic:

  * ``parse_sshd_effective_allowlists`` — parse the four allow/deny directives
    out of ``sshd -T`` effective-config output (deterministic, unit-testable).
  * ``evaluate_login_allowlist`` — given a login, its remote group membership,
    and the parsed directives, decide whether sshd would reject the login and
    why, following sshd's own evaluation order.
  * ``diagnose_login_allowlist`` — the service entry point: run the probes over
    a bootstrap SSH connection, parse, evaluate, and return a structured,
    operator-actionable result with remediation guidance.

Nothing here edits customer sshd policy. Detection and reporting only.
"""

from __future__ import annotations

import fnmatch
import logging
import shlex
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# The four native account allow-list directives sshd evaluates before it will
# even look at the offered certificate/key. ``sshd -T`` lower-cases directive
# names and only emits these four when they are actually configured (they have
# no default), so an absent key means "not restricted".
_ALLOWLIST_DIRECTIVES = ("allowusers", "allowgroups", "denyusers", "denygroups")

# Bounded probe timeout — we never want a diagnostic to hang a Connect attempt.
PROBE_TIMEOUT_S = 15


@dataclass
class AllowlistDenial:
    """A single, concrete reason sshd would reject ``login``.

    ``kind`` is one of ``allow_users`` / ``allow_groups`` / ``deny_users`` /
    ``deny_groups``. ``directive_value`` is the effective directive tokens as
    sshd reports them (e.g. ``"praxis admin"``). ``matched_group`` is set only
    for the deny-groups case, naming the offending group. ``source_file`` is a
    best-effort path if we could locate the directive; ``None`` when we could
    not (kept honest rather than guessed).
    """

    kind: str
    login: str
    directive_value: str
    matched_group: Optional[str] = None
    source_file: Optional[str] = None

    def message(self, hostname: Optional[str] = None) -> str:
        where = f" on {hostname}" if hostname else ""
        src = f" in {self.source_file}" if self.source_file else ""
        if self.kind == "allow_users":
            return (
                f"login '{self.login}' is blocked by sshd AllowUsers policy{where}"
                f"{src}: AllowUsers is set to '{self.directive_value}' and does not "
                f"include '{self.login}'."
            )
        if self.kind == "allow_groups":
            return (
                f"login '{self.login}' is blocked by sshd AllowGroups policy{where}"
                f"{src}: AllowGroups is set to '{self.directive_value}' and none of "
                f"the account's groups are listed."
            )
        if self.kind == "deny_users":
            return (
                f"login '{self.login}' is blocked by sshd DenyUsers policy{where}"
                f"{src}: DenyUsers is set to '{self.directive_value}'."
            )
        if self.kind == "deny_groups":
            grp = f" (group '{self.matched_group}')" if self.matched_group else ""
            return (
                f"login '{self.login}' is blocked by sshd DenyGroups policy{where}"
                f"{src}: DenyGroups is set to '{self.directive_value}'{grp}."
            )
        return f"login '{self.login}' is blocked by sshd account policy{where}."


@dataclass
class AllowlistDiagnosis:
    """Result of an allow-list probe for one login.

    ``checked`` is False when we could not run the probe at all (no bootstrap
    connection, sshd -T unavailable); in that case ``blocked`` is False and the
    caller must not claim an allow-list denial. ``blocked`` True carries a
    populated ``denial``.
    """

    login: str
    checked: bool
    blocked: bool
    denial: Optional[AllowlistDenial] = None
    indeterminate_reason: Optional[str] = None
    remediation: List[str] = field(default_factory=list)

    def to_dict(self, hostname: Optional[str] = None) -> Dict[str, object]:
        return {
            "login": self.login,
            "checked": self.checked,
            "blocked": self.blocked,
            "reason": self.denial.message(hostname) if self.denial else None,
            "kind": self.denial.kind if self.denial else None,
            "directive_value": self.denial.directive_value if self.denial else None,
            "source_file": self.denial.source_file if self.denial else None,
            "indeterminate_reason": self.indeterminate_reason,
            "remediation": self.remediation,
        }


# --------------------------------------------------------------- parsing


def parse_sshd_effective_allowlists(
    sshd_t_output: str,
) -> Dict[str, Optional[List[str]]]:
    """Extract the account allow/deny directives from ``sshd -T`` output.

    Returns a dict with keys ``allow_users`` / ``allow_groups`` /
    ``deny_users`` / ``deny_groups``. A value of ``None`` means the directive
    is not configured (sshd omits it); a list (possibly empty) means it is set
    to those tokens. Tokens accumulate across repeated lines defensively, even
    though ``sshd -T`` normally collapses each directive onto one line.
    """
    result: Dict[str, Optional[List[str]]] = {
        "allow_users": None,
        "allow_groups": None,
        "deny_users": None,
        "deny_groups": None,
    }
    key_map = {
        "allowusers": "allow_users",
        "allowgroups": "allow_groups",
        "denyusers": "deny_users",
        "denygroups": "deny_groups",
    }
    for raw in sshd_t_output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        directive = parts[0].lower()
        if directive not in _ALLOWLIST_DIRECTIVES:
            continue
        out_key = key_map[directive]
        tokens = parts[1:]
        if result[out_key] is None:
            result[out_key] = []
        result[out_key].extend(tokens)  # type: ignore[union-attr]
    return result


def _pattern_matches(pattern: str, value: str) -> bool:
    """Match a single sshd allow/deny pattern against a value.

    sshd uses shell-style globbing (``*`` and ``?``). ``AllowUsers`` entries may
    carry a ``user@host`` form; we compare only the user portion since the host
    portion depends on the connecting address, which we evaluate via
    ``sshd -T -C`` upstream. Matching is case-sensitive to mirror sshd.
    """
    user_part = pattern.split("@", 1)[0] if "@" in pattern else pattern
    if not user_part:
        return False
    return fnmatch.fnmatchcase(value, user_part)


def _list_matches(patterns: List[str], value: str) -> bool:
    """True if ``value`` is allowed by an sshd pattern list.

    Honours negated patterns (leading ``!``): a negated match is an immediate
    reject; otherwise any positive match accepts.
    """
    matched = False
    for pattern in patterns:
        if not pattern:
            continue
        if pattern.startswith("!"):
            if _pattern_matches(pattern[1:], value):
                return False
        elif _pattern_matches(pattern, value):
            matched = True
    return matched


def evaluate_login_allowlist(
    login: str,
    user_groups: List[str],
    allowlists: Dict[str, Optional[List[str]]],
) -> Optional[AllowlistDenial]:
    """Decide whether sshd would reject ``login`` given the parsed allow-lists.

    Follows sshd's documented order: DenyUsers, AllowUsers, DenyGroups,
    AllowGroups. Returns the first matching denial, or ``None`` if the login
    passes every configured gate (or no gates are configured).
    """
    deny_users = allowlists.get("deny_users")
    allow_users = allowlists.get("allow_users")
    deny_groups = allowlists.get("deny_groups")
    allow_groups = allowlists.get("allow_groups")

    # 1. DenyUsers — any match rejects.
    if deny_users:
        for pattern in deny_users:
            neg = pattern.startswith("!")
            core = pattern[1:] if neg else pattern
            if not neg and _pattern_matches(core, login):
                return AllowlistDenial(
                    kind="deny_users",
                    login=login,
                    directive_value=" ".join(deny_users),
                )

    # 2. AllowUsers — if set, login must match a positive (non-negated) pattern.
    if allow_users is not None and not _list_matches(allow_users, login):
        return AllowlistDenial(
            kind="allow_users",
            login=login,
            directive_value=" ".join(allow_users),
        )

    # 3. DenyGroups — any of the account's groups matching rejects.
    if deny_groups:
        for group in user_groups:
            if _list_matches([p for p in deny_groups if not p.startswith("!")], group):
                return AllowlistDenial(
                    kind="deny_groups",
                    login=login,
                    directive_value=" ".join(deny_groups),
                    matched_group=group,
                )

    # 4. AllowGroups — if set, at least one of the account's groups must match.
    if allow_groups is not None:
        if not any(_list_matches(allow_groups, group) for group in user_groups):
            return AllowlistDenial(
                kind="allow_groups",
                login=login,
                directive_value=" ".join(allow_groups),
            )

    return None


def remediation_for(denial: AllowlistDenial) -> List[str]:
    """Operator-facing remediation options for a denial.

    Praxis never edits customer sshd policy automatically; these are choices the
    operator makes on the host.
    """
    login = denial.login
    base = [
        f"Add '{login}' to sshd AllowUsers "
        f"(e.g. in {denial.source_file or '/etc/ssh/sshd_config.d/'}), then reload sshd.",
        "Or switch the host to AllowGroups with a Praxis-managed or operator-specified "
        f"group and add '{login}' to it.",
        "Or leave host sshd policy unchanged and treat this access binding as "
        "unhealthy — the broker cannot connect this login until the allow-list permits it.",
    ]
    if denial.kind in ("deny_users", "deny_groups"):
        base.insert(
            0,
            f"Remove '{login}' from the sshd "
            f"{'DenyUsers' if denial.kind == 'deny_users' else 'DenyGroups'} directive "
            f"({denial.directive_value}) on the host, then reload sshd.",
        )
    return base


# ------------------------------------------------------ remote probing


def _default_runner(client, timeout: int) -> Callable[[str], Dict[str, object]]:
    """Wrap a paramiko client into a simple ``run(cmd) -> {...}`` callable."""

    def run(command: str) -> Dict[str, object]:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return {"exit_code": exit_code, "stdout": out, "stderr": err}

    return run


def probe_effective_allowlists(
    run: Callable[[str], Dict[str, object]],
    login: str,
) -> Optional[Dict[str, Optional[List[str]]]]:
    """Run ``sshd -T`` for ``login`` and parse the allow-lists.

    Prefers ``sshd -T -C user=<login>`` so ``Match user`` blocks are expanded
    for this specific login; falls back to a plain ``sshd -T`` if the
    connection-spec form is rejected by the host's sshd. Returns ``None`` when
    neither form yields usable output (old sshd, no sudo, etc.), so the caller
    can report "indeterminate" rather than guess.
    """
    quoted_login = shlex.quote(login)
    attempts = (
        f"sudo -n sshd -T -C user={quoted_login} 2>/dev/null",
        "sudo -n sshd -T 2>/dev/null",
    )
    for cmd in attempts:
        res = run(cmd)
        out = str(res.get("stdout") or "")
        if res.get("exit_code") == 0 and out.strip():
            return parse_sshd_effective_allowlists(out)
    return None


def probe_user_groups(
    run: Callable[[str], Dict[str, object]],
    login: str,
) -> List[str]:
    """Return the remote group names for ``login`` (empty if the probe fails)."""
    res = run(f"id -nG {shlex.quote(login)} 2>/dev/null")
    if res.get("exit_code") != 0:
        return []
    return [g for g in str(res.get("stdout") or "").split() if g]


def locate_directive_source(
    run: Callable[[str], Dict[str, object]],
    kind: str,
) -> Optional[str]:
    """Best-effort: find which sshd config file declares the directive.

    Greps the main config and the drop-in directory. Returns the first matching
    file path, or ``None`` — the diagnostic stays honest and does not fabricate
    a path when the source cannot be pinned down.
    """
    directive = {
        "allow_users": "AllowUsers",
        "allow_groups": "AllowGroups",
        "deny_users": "DenyUsers",
        "deny_groups": "DenyGroups",
    }.get(kind)
    if not directive:
        return None
    # -il: case-insensitive, list filenames only. Word-ish anchor via leading
    # whitespace/newline handled by grep's default line match on the directive.
    cmd = (
        "sudo -n grep -RilE "
        f"'^[[:space:]]*{directive}[[:space:]]' "
        "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | head -n1"
    )
    res = run(cmd)
    if res.get("exit_code") == 0:
        path = str(res.get("stdout") or "").strip().splitlines()
        if path:
            return path[0].strip()
    return None


def diagnose_login_allowlist(
    run: Callable[[str], Dict[str, object]],
    login: str,
) -> AllowlistDiagnosis:
    """Full allow-list diagnosis for ``login`` given a command runner.

    The runner is any ``run(command) -> {"exit_code", "stdout", "stderr"}``
    callable bound to a working bootstrap SSH session on the target host. This
    signature keeps the logic pure and unit-testable without a live host.
    """
    allowlists = probe_effective_allowlists(run, login)
    if allowlists is None:
        return AllowlistDiagnosis(
            login=login,
            checked=False,
            blocked=False,
            indeterminate_reason=(
                "could not read effective sshd policy (sshd -T unavailable or "
                "insufficient privilege); allow-list compatibility unverified"
            ),
        )

    user_groups = probe_user_groups(run, login)
    denial = evaluate_login_allowlist(login, user_groups, allowlists)
    if denial is None:
        return AllowlistDiagnosis(login=login, checked=True, blocked=False)

    # Enrich with the source file only when a denial actually exists — cheap
    # since it runs once per blocked login, and it makes the message concrete.
    try:
        denial.source_file = locate_directive_source(run, denial.kind)
    except Exception:  # pylint: disable=broad-except
        denial.source_file = None

    return AllowlistDiagnosis(
        login=login,
        checked=True,
        blocked=True,
        denial=denial,
        remediation=remediation_for(denial),
    )


def runner_for_client(client, timeout: int = PROBE_TIMEOUT_S):
    """Public helper to build a runner from a paramiko client."""
    return _default_runner(client, timeout)
