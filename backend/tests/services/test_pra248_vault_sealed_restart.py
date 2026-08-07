"""PRA-248: an initialized-but-sealed Vault (`vault status` rc 2) must not exit
init-vault.sh early under ``set -e``.

Exercises the sourced ``vault/scripts/vault-status.sh`` helper with a fake
``vault`` + ``jq`` (no real Vault). Proves the restart-reliability contract:

- rc 0 (unsealed) -> prints the ``.initialized`` value, returns 0;
- rc 2 (sealed)   -> prints the ``.initialized`` value, returns 0 (the fix: a
  sealed status is a normal restart state and routes to the unseal branch);
- any other rc (e.g. rc 1 unreachable), non-JSON status output, or a
  missing/invalid ``.initialized`` field -> fails closed (returns nonzero).
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest

_LIB = Path(
    os.environ.get("PRAXIS_VAULT_STATUS_LIB")
    or Path(__file__).resolve().parents[3] / "vault" / "scripts" / "vault-status.sh"
)

if not _LIB.exists():  # pragma: no cover - only when repo root/vault dir absent
    pytest.skip("vault/scripts/vault-status.sh not found", allow_module_level=True)


def _mk_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _fake_bin(tmp_path: Path) -> Path:
    """A fake `bao` (status output/rc from env) + a hermetic `jq` shim (the
    backend/CI image has no jq). PRA-311: the bundled runtime is OpenBao, and
    vault-status.sh now calls `bao status`."""
    binp = tmp_path / "bin"
    binp.mkdir(exist_ok=True)
    _mk_exec(
        binp / "bao",
        "#!/bin/sh\n"
        'if [ "$1" = "status" ]; then\n'
        '  [ -n "$FAKE_VAULT_STATUS_JSON" ] && printf "%s\\n" "$FAKE_VAULT_STATUS_JSON"\n'
        '  exit "${FAKE_VAULT_STATUS_RC:-0}"\n'
        "fi\n"
        "exit 0\n",
    )
    _mk_exec(
        binp / "jq",
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        "flt = sys.argv[-1].lstrip('.')\n"
        "try:\n"
        "    d = json.load(sys.stdin)\n"
        "except Exception:\n"
        "    sys.exit(4)\n"  # parse error -> jq nonzero
        "v = d.get(flt) if isinstance(d, dict) else None\n"
        "sys.stdout.write('null' if v is None else "
        "('true' if v is True else ('false' if v is False else str(v))))\n"
        "sys.stdout.write('\\n')\n",
    )
    return binp


def _run(tmp_path, rc, json_out):
    binp = _fake_bin(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{binp}{os.pathsep}{env['PATH']}"
    env["FAKE_VAULT_STATUS_RC"] = str(rc)
    if json_out is not None:
        env["FAKE_VAULT_STATUS_JSON"] = json_out
    else:
        env.pop("FAKE_VAULT_STATUS_JSON", None)
    return subprocess.run(
        ["sh", "-c", f'. "{_LIB}"; vault_initialized_state'],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_unsealed_rc0_initialized_false(tmp_path):
    r = _run(tmp_path, 0, '{"initialized":false,"sealed":false}')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "false"


def test_sealed_rc2_initialized_true_does_not_fail(tmp_path):
    # The core PRA-248 fix: a sealed (rc 2) initialized Vault is accepted and its
    # .initialized value is reported, so init-vault.sh reaches the unseal branch.
    r = _run(tmp_path, 2, '{"initialized":true,"sealed":true}')
    assert r.returncode == 0, f"sealed rc 2 must not fail: {r.stderr}"
    assert r.stdout.strip() == "true"


def test_unsealed_rc0_initialized_true(tmp_path):
    r = _run(tmp_path, 0, '{"initialized":true,"sealed":false}')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "true"


def test_unreachable_rc1_fails_closed(tmp_path):
    r = _run(tmp_path, 1, None)
    assert r.returncode != 0
    assert "unreachable" in r.stderr.lower() or "failed" in r.stderr.lower()


def test_other_rc_fails_closed(tmp_path):
    r = _run(tmp_path, 7, '{"initialized":true}')
    assert r.returncode != 0


def test_malformed_json_fails_closed(tmp_path):
    r = _run(tmp_path, 2, "this is not json")
    assert r.returncode != 0
    assert "parse" in r.stderr.lower()


def test_missing_initialized_field_fails_closed(tmp_path):
    r = _run(tmp_path, 0, '{"sealed":true}')
    assert r.returncode != 0
    assert "initialized" in r.stderr.lower()
