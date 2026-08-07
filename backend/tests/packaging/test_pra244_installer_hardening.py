"""PRA-244: the root-run agent installer must be argv-safe (no shell evaluation).

`agent/packaging/install.sh` runs as root during agent rollout. It previously
built shell command strings and ran them through ``eval``, so any operator- or
attacker-influenced value (paths, service name, broker/backend URLs) that reached
those strings could execute arbitrary commands as root.

These tests are a **security regression guard**. They drive the real installer in
``--dry-run`` (which mutates nothing and, by design, does not require root) with
hostile arguments containing ``;``, ``&&``, ``|``, backticks, ``$()``, quotes,
whitespace, and redirection, and assert that:

- the source contains no ``eval``;
- injected shell syntax never executes (a marker file is never created);
- injected syntax is shown safely shell-quoted in dry-run output;
- invalid ``--service-name`` values are rejected before any systemd/systemctl use;
- ``--dry-run`` and ``--no-systemd`` still work.

The installer is invoked as ``bash install.sh``; a throwaway executable stands in
for the agent binary so preflight's existence/executable checks pass.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[3] / "agent" / "packaging" / "install.sh"

if sys.platform != "linux":  # pragma: no cover - installer is Linux-only
    pytest.skip("agent installer is Linux-only", allow_module_level=True)
if not INSTALL_SH.exists():  # pragma: no cover - repo layout guard
    pytest.skip("install.sh not found", allow_module_level=True)
if shutil.which("bash") is None:  # pragma: no cover - CI/runner has bash
    pytest.skip("bash not available", allow_module_level=True)


def _fake_binary(dir_path: Path, name: str = "praxis-agent") -> Path:
    """A stand-in agent binary that answers --version, so preflight's -f/-x pass."""
    p = dir_path / name
    p.write_text("#!/bin/sh\necho 'praxis-agent 0.0-test'\n")
    p.chmod(0o755)
    return p


def _run(args, cwd=None):
    return subprocess.run(
        ["bash", str(INSTALL_SH), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=60,
    )


# Each suffix tries to break out of the argument and run `touch {m}`. Under argv
# execution none of these can execute. `{m}` is filled with a per-case marker path.
_HOSTILE_SUFFIX_TEMPLATES = [
    "; touch {m}",
    "&& touch {m}",
    "| touch {m}",
    "$(touch {m})",
    "`touch {m}`",
    '"; touch {m}; "',
    "'; touch {m}; '",
    "> {m}",
    "\n touch {m}",  # newline: also an injection vector for the unit file
]


# --------------------------------------------------- source guard


def test_installer_source_has_no_eval():
    text = INSTALL_SH.read_text()
    assert re.search(r"\beval\b", text) is None, "install.sh must not use eval"


# --------------------------------------------------- baseline behavior


def test_dry_run_no_systemd_happy_path(tmp_path):
    binary = _fake_binary(tmp_path)
    r = _run(
        [
            "--binary",
            str(binary),
            "--config-dir",
            str(tmp_path / "cfg"),
            "--bin-path",
            str(tmp_path / "bin" / "praxis-agent"),
            "--no-systemd",
            "--dry-run",
        ]
    )
    assert r.returncode == 0, r.stderr
    assert "DRY-RUN" in r.stdout
    assert "done" in r.stdout


def test_dry_run_output_is_shell_quoted(tmp_path):
    binary = _fake_binary(tmp_path)
    # A config dir with spaces + a semicolon must appear escaped in the DRY-RUN
    # line (proof it's displayed, not evaluated).
    cfg = str(tmp_path / "cfg dir; x")
    r = _run(
        ["--binary", str(binary), "--config-dir", cfg, "--no-systemd", "--dry-run"]
    )
    assert r.returncode == 0, r.stderr
    assert "DRY-RUN $" in r.stdout
    # printf %q escapes the semicolon and space; the raw unescaped sequence must
    # not appear on a DRY-RUN command line.
    dry_lines = [ln for ln in r.stdout.splitlines() if "DRY-RUN $" in ln]
    assert dry_lines
    assert any("\\;" in ln or "\\ " in ln for ln in dry_lines)


# --------------------------------------------------- hostile injection


@pytest.mark.parametrize("flag", ["--config-dir", "--bin-path"])
def test_hostile_path_flag_does_not_execute(tmp_path, flag):
    binary = _fake_binary(tmp_path)
    for i, tmpl in enumerate(_HOSTILE_SUFFIX_TEMPLATES):
        marker = tmp_path / f"MARK_{i}"
        if marker.exists():
            marker.unlink()
        value = f"{tmp_path}/target" + tmpl.format(m=marker)
        r = _run(
            [
                "--binary",
                str(binary),
                flag,
                value,
                "--no-systemd",
                "--dry-run",
            ]
        )
        assert not marker.exists(), (
            f"{flag} {value!r} executed injected command (rc={r.returncode})\n"
            f"stdout={r.stdout}\nstderr={r.stderr}"
        )


@pytest.mark.parametrize("flag", ["--broker-url", "--backend-url"])
def test_hostile_url_does_not_execute(tmp_path, flag):
    binary = _fake_binary(tmp_path)
    for i, tmpl in enumerate(_HOSTILE_SUFFIX_TEMPLATES):
        marker = tmp_path / f"URLMARK_{i}"
        if marker.exists():
            marker.unlink()
        value = "wss://host/path" + tmpl.format(m=marker)
        r = _run(
            [
                "--binary",
                str(binary),
                "--config-dir",
                str(tmp_path / "cfg"),
                flag,
                value,
                "--no-systemd",
                "--dry-run",
            ]
        )
        assert not marker.exists(), (
            f"{flag} {value!r} executed injected command\n"
            f"stdout={r.stdout}\nstderr={r.stderr}"
        )


def test_hostile_binary_path_does_not_execute(tmp_path):
    # The binary must exist for preflight to pass, so give it a filename that is
    # itself hostile (semicolon + command substitution + spaces). Argv execution
    # means it is only ever a literal path, never a shell fragment.
    marker = tmp_path / "BINMARK"
    hostile_dir = tmp_path / "d"
    hostile_dir.mkdir()
    binary = _fake_binary(hostile_dir, name="a; touch $(echo BINMARK) b")
    r = _run(
        [
            "--binary",
            str(binary),
            "--config-dir",
            str(tmp_path / "cfg"),
            "--no-systemd",
            "--dry-run",
        ],
        cwd=str(tmp_path),
    )
    assert not marker.exists(), f"hostile binary path executed\n{r.stdout}\n{r.stderr}"
    assert not (tmp_path / "BINMARK").exists()
    assert r.returncode == 0, r.stderr


# --------------------------------------------------- option smuggling (leading dash)


@pytest.mark.parametrize("flag", ["--config-dir", "--bin-path"])
def test_leading_dash_path_is_option_safe(tmp_path, flag):
    # A path beginning with '-' must be treated as an operand, not parsed as an
    # option by install/mv. Every DRY-RUN command line carrying the value must
    # place a '--' separator before it.
    binary = _fake_binary(tmp_path)
    value = "-rf-oops"
    marker = tmp_path / "DASHMARK"
    r = _run(["--binary", str(binary), flag, value, "--no-systemd", "--dry-run"])
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert not marker.exists()
    dash_lines = [
        ln for ln in r.stdout.splitlines() if "DRY-RUN $" in ln and value in ln
    ]
    assert dash_lines, f"value never reached a command line:\n{r.stdout}"
    for ln in dash_lines:
        assert " -- " in ln, f"missing '--' operand separator: {ln}"


def test_leading_dash_binary_reaches_sha256sum_safely(tmp_path):
    # sha_of() runs even in dry-run. A relative binary path starting with '-' must
    # not be parsed as a sha256sum option.
    binname = "-dash-agent"
    b = tmp_path / binname
    b.write_text("#!/bin/sh\necho v\n")
    b.chmod(0o755)
    marker = tmp_path / "BINDASH"
    r = _run(
        [
            "--binary",
            binname,  # relative, so BINARY_SRC itself starts with '-'
            "--config-dir",
            str(tmp_path / "cfg"),
            "--no-systemd",
            "--dry-run",
        ],
        cwd=str(tmp_path),
    )
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "invalid option" not in r.stderr.lower()
    assert "unrecognized option" not in r.stderr.lower()
    assert not marker.exists()
    assert "done" in r.stdout


# --------------------------------------------------- service-name validation


@pytest.mark.parametrize(
    "name",
    [
        "../evil",  # path traversal
        "a/b",  # slash
        "a;touch x",  # command separator
        "a b",  # whitespace
        "-rf",  # leading dash (systemctl option smuggling)
        "a$(id)",  # command substitution
        "a`id`",  # backtick
        "a|b",  # pipe
        "a>b",  # redirection
        ".hidden",  # leading dot (not alphanumeric start)
        "",  # empty
    ],
)
def test_invalid_service_name_rejected(tmp_path, name):
    binary = _fake_binary(tmp_path)
    marker = tmp_path / "SVCMARK"
    r = _run(
        [
            "--binary",
            str(binary),
            "--service-name",
            name,
            "--no-systemd",
            "--dry-run",
        ]
    )
    assert r.returncode != 0, f"service name {name!r} should be rejected: {r.stdout}"
    assert "service-name" in r.stderr
    assert not marker.exists()


@pytest.mark.parametrize("name", ["praxis-agent", "my.agent_1", "Agent-2", "svc"])
def test_valid_service_name_accepted(tmp_path, name):
    binary = _fake_binary(tmp_path)
    r = _run(
        [
            "--binary",
            str(binary),
            "--config-dir",
            str(tmp_path / "cfg"),
            "--service-name",
            name,
            "--no-systemd",
            "--dry-run",
        ]
    )
    assert r.returncode == 0, r.stderr


# --------------------------------------------------- control-char rejection


@pytest.mark.parametrize("flag", ["--config-dir", "--bin-path"])
def test_newline_in_path_rejected(tmp_path, flag):
    # A newline in a path could inject extra directives into the rendered unit.
    binary = _fake_binary(tmp_path)
    r = _run(
        [
            "--binary",
            str(binary),
            flag,
            "/tmp/ok\nExecStartPre=/bin/evil",
            "--no-systemd",
            "--dry-run",
        ]
    )
    assert r.returncode != 0
    assert "newline" in r.stderr or "control" in r.stderr
