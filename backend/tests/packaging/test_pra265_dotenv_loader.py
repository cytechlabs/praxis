"""PRA-265: the container entrypoint must load ``/app/.env`` as DATA, not shell.

The old ``start.prod.sh`` loaded the env file with
``eval "$(sed ... /app/.env ...)"``, so a value like
``DATABASE_URL=$(touch /tmp/pwned)`` executed as a shell command at boot. These
tests are a security regression guard for the shared ``scripts/load_dotenv.py``
loader and the entrypoint wiring:

- hostile values (``$()``, backticks, ``;`` / ``&&`` / ``|``, redirects, quotes,
  whitespace) are exported LITERALLY and never execute a command;
- valid dotenv syntax (comments, blank lines, CRLF, quoted values, spaces) parses
  correctly;
- malformed keys are skipped by explicit policy;
- the entrypoints call the loader and contain no shell-eval of the env file.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
LOADER = SCRIPTS_DIR / "load_dotenv.py"
# PRA-299 retired the dev entrypoint (start.sh); start.prod.sh is the sole
# container entrypoint.
START_PROD = SCRIPTS_DIR / "start.prod.sh"

if not LOADER.exists():  # pragma: no cover - repo layout guard
    pytest.skip("load_dotenv.py not found", allow_module_level=True)

sys.path.insert(0, str(SCRIPTS_DIR))
import load_dotenv  # noqa: E402

# --------------------------------------------------- unit: parse_env_file


def _write(tmp_path, text: str) -> str:
    p = tmp_path / ".env"
    p.write_bytes(text.encode())
    return str(p)


def test_valid_dotenv_parsing(tmp_path):
    env = _write(
        tmp_path,
        "# a comment\n"
        "\n"
        "   \n"
        "DATABASE_URL=postgresql://u:p@db:5432/praxis\n"
        'QUOTED="hello world"\n'
        "SINGLE='literal value'\n"
        "SPACED=a b c\n"
        "export EXPORTED=from-export-line\n"
        "PUNCT=a-b_c.d:e/f\n",
    )
    values = load_dotenv.parse_env_file(env)
    assert values["DATABASE_URL"] == "postgresql://u:p@db:5432/praxis"
    assert values["QUOTED"] == "hello world"
    assert values["SINGLE"] == "literal value"
    assert values["SPACED"] == "a b c"
    assert values["EXPORTED"] == "from-export-line"
    assert values["PUNCT"] == "a-b_c.d:e/f"


def test_crlf_line_endings(tmp_path):
    env = _write(tmp_path, "FOO=bar\r\nBAZ=qux\r\n")
    values = load_dotenv.parse_env_file(env)
    assert values["FOO"] == "bar"
    assert values["BAZ"] == "qux"


def test_malformed_keys_skipped(tmp_path):
    env = _write(tmp_path, "9NUM=x\nbad key=y\nGOOD=z\n")
    values = load_dotenv.parse_env_file(env)
    assert values.get("GOOD") == "z"
    assert "9NUM" not in values
    assert "bad key" not in values


def test_missing_file_is_empty(tmp_path):
    assert load_dotenv.parse_env_file(str(tmp_path / "nope.env")) == {}


@pytest.mark.parametrize(
    "raw",
    [
        "V=$(touch {m})",
        "V=`touch {m}`",
        "V=x; touch {m}",
        "V=x && touch {m}",
        "V=x | touch {m}",
        "V=x > {m}",
        'V="$(touch {m})"',
    ],
)
def test_hostile_values_parsed_literally(tmp_path, raw):
    marker = tmp_path / "PARSED_MARK"
    env = _write(tmp_path, raw.format(m=marker) + "\n")
    values = load_dotenv.parse_env_file(env)
    # No shell ran during parsing; the value is a plain string.
    assert not marker.exists()
    assert "V" in values
    assert str(marker) in values["V"] or "touch" in values["V"]


# --------------------------------------------------- integration: loader execs


def _run_loader(env_path, *command):
    return subprocess.run(
        ["python", str(LOADER), str(env_path), "--", *command],
        capture_output=True,
        text=True,
        timeout=30,
    )


_READBACK = "import os,sys; sys.stdout.write(os.environ.get(sys.argv[1], '<unset>'))"


def test_hostile_value_does_not_execute_on_load(tmp_path):
    marker = tmp_path / "EXEC_MARK"
    env = _write(tmp_path, f"DATABASE_URL=$(touch {marker})\n")
    r = _run_loader(env, "python", "-c", _READBACK, "DATABASE_URL")
    assert r.returncode == 0, r.stderr
    assert not marker.exists(), "dotenv value executed a command"
    assert r.stdout == f"$(touch {marker})"  # exported literally


@pytest.mark.parametrize(
    "template",
    [
        "K=`touch {m}`",
        "K=x; touch {m}",
        "K=x && touch {m}",
        "K=x | touch {m}",
        "K=x > {m}",
    ],
)
def test_hostile_variants_do_not_execute_on_load(tmp_path, template):
    marker = tmp_path / "V_MARK"
    if marker.exists():
        marker.unlink()
    env = _write(tmp_path, template.format(m=marker) + "\n")
    r = _run_loader(env, "python", "-c", _READBACK, "K")
    assert not marker.exists(), f"{template!r} executed\n{r.stdout}\n{r.stderr}"


def test_loader_execs_command_with_merged_env(tmp_path):
    env = _write(tmp_path, "PRA265_TESTVAR=it-works\n")
    r = _run_loader(env, "python", "-c", _READBACK, "PRA265_TESTVAR")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "it-works"


def test_missing_env_file_still_execs_command(tmp_path):
    r = _run_loader(tmp_path / "absent.env", "python", "-c", "print('ran')")
    assert r.returncode == 0, r.stderr
    assert "ran" in r.stdout


def test_no_command_after_separator_fails(tmp_path):
    env = _write(tmp_path, "FOO=bar\n")
    r = subprocess.run(
        ["python", str(LOADER), str(env), "--"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 2


# --------------------------------------------------- exec-loop guard (PRA-265 P2)


def test_dotenv_cannot_clear_exec_loop_guard(tmp_path):
    # The entrypoint sets PRAXIS_DOTENV_LOADED=1 before exec'ing the loader. A
    # hostile/misconfigured .env line must NOT be able to clear it (which would
    # loop startup and never reach the DB wait / migrations).
    env = _write(tmp_path, "PRAXIS_DOTENV_LOADED=\nNORMAL=ok\n")
    child_env = {**os.environ, "PRAXIS_DOTENV_LOADED": "1"}
    r = subprocess.run(
        [
            "python",
            str(LOADER),
            str(env),
            "--",
            "python",
            "-c",
            _READBACK,
            "PRAXIS_DOTENV_LOADED",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=child_env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "1", "a .env value cleared the exec-loop guard"


def test_loader_asserts_guard_even_if_shell_did_not_set_it(tmp_path):
    # Defense in depth: the loader itself guarantees the guard is set before exec.
    env = _write(tmp_path, "NORMAL=ok\n")
    child_env = {k: v for k, v in os.environ.items() if k != "PRAXIS_DOTENV_LOADED"}
    r = subprocess.run(
        [
            "python",
            str(LOADER),
            str(env),
            "--",
            "python",
            "-c",
            _READBACK,
            "PRAXIS_DOTENV_LOADED",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=child_env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "1"


# --------------------------------------------------- entrypoint wiring (static)


def test_entrypoint_uses_safe_loader_and_no_eval():
    body = START_PROD.read_text()
    assert "load_dotenv.py" in body, "start.prod.sh does not call the safe loader"
    assert "PRAXIS_DOTENV_LOADED" in body, "start.prod.sh missing exec-loop guard"
    # No shell-eval of the env file remains.
    assert "eval " not in body, "start.prod.sh still uses eval"
    assert "source /app/.env" not in body
    assert ". /app/.env" not in body


def test_prod_entrypoint_still_reaches_db_and_migrations():
    # The security change must not disturb the existing startup flow.
    body = START_PROD.read_text()
    assert "Waiting for database to be ready" in body
    assert "alembic upgrade head" in body
