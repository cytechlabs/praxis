"""PRA-241: bundled-Vault operator recovery material is split from runtime creds.

Security regression guard proving that the backend and agent-broker runtime
containers cannot read Vault root/unseal recovery material:

- the ``vault_recovery`` volume (root token + unseal keys) is mounted ONLY into
  the Vault container, never into backend or agent-broker (base + prod compose);
- ``init-vault.sh`` writes ``root-token`` / ``init-keys.json`` to the operator
  recovery dir (default ``/vault/recovery``) with a restrictive umask, never to
  the app-readable ``/vault/data``, and migrates any legacy copies off it;
- the scoped ``backend-token`` and public cert material stay in ``/vault/data``.

Compose files are parsed with a small indent-based reader (no PyYAML dependency,
which is absent from the backend/CI image) so the assertions run in CI.
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_PROD = REPO / "docker-compose.prod.yml"
INIT_SH = REPO / "vault" / "scripts" / "init-vault.sh"

if not COMPOSE.exists() or not INIT_SH.exists():  # pragma: no cover - repo layout
    pytest.skip(
        "repo root not available (compose / init-vault.sh missing)",
        allow_module_level=True,
    )


def _service_block(text: str, name: str) -> str:
    """Return the lines of a 2-space-indented compose service block for ``name``,
    stopping at the next service header or the next top-level section."""
    header = re.compile(rf"^  {re.escape(name)}:\s*$")
    next_two_space = re.compile(r"^  \S")
    out: list[str] = []
    in_block = False
    for ln in text.splitlines():
        if not in_block:
            if header.match(ln):
                in_block = True
            continue
        if next_two_space.match(ln) or (
            ln and not ln.startswith(" ") and ln.rstrip().endswith(":")
        ):
            break
        out.append(ln)
    return "\n".join(out)


def _mentions_recovery(block: str) -> bool:
    return "vault_recovery" in block or "/vault/recovery" in block


# --------------------------------------------------- compose mounts


def test_recovery_volume_mounted_only_into_vault():
    text = COMPOSE.read_text()
    vault = _service_block(text, "vault")
    backend = _service_block(text, "backend")
    broker = _service_block(text, "agent-broker")

    assert (
        "vault_recovery:/vault/recovery" in vault
    ), "vault must mount the recovery volume"
    assert not _mentions_recovery(backend), "backend must NOT mount recovery material"
    assert not _mentions_recovery(
        broker
    ), "agent-broker must NOT mount recovery material"
    # Top-level volume declared.
    assert re.search(
        r"^  vault_recovery:\s*$", text, re.M
    ), "vault_recovery volume not declared"


def test_backend_and_broker_still_mount_vault_data_ro():
    text = COMPOSE.read_text()
    for svc in ("backend", "agent-broker"):
        block = _service_block(text, svc)
        assert (
            "vault_data:/vault/data:ro" in block
        ), f"{svc} lost vault_data:/vault/data:ro"


def test_prod_backend_override_excludes_recovery():
    if not COMPOSE_PROD.exists():  # pragma: no cover
        pytest.skip("docker-compose.prod.yml missing")
    text = COMPOSE_PROD.read_text()
    backend = _service_block(text, "backend")
    # Prod backend uses `volumes: !override` — assert it pins vault_data:ro only.
    assert "vault_data:/vault/data:ro" in backend
    assert not _mentions_recovery(
        backend
    ), "prod backend must NOT mount recovery material"
    # Prod vault must not strip the base recovery mount (no volumes override there).
    vault = _service_block(text, "vault")
    assert (
        "volumes:" not in vault
    ), "prod vault should inherit base volumes (incl. recovery)"


# --------------------------------------------------- init-vault.sh behavior


def test_init_writes_recovery_material_outside_app_volume():
    src = INIT_SH.read_text()
    # Recovery material is never written to (or read from) the app-readable path.
    assert "/vault/data/root-token" not in src
    assert "/vault/data/init-keys.json" not in src
    # Recovery dir defaults outside /vault/data.
    assert "PRAXIS_VAULT_RECOVERY_DIR:-/vault/recovery" in src
    assert 'ROOT_TOKEN_FILE="$RECOVERY_DIR/root-token"' in src
    assert 'INIT_KEYS_FILE="$RECOVERY_DIR/init-keys.json"' in src
    # Recovery writes use a restrictive umask.
    assert "umask 077" in src


def test_init_migrates_legacy_material_off_app_volume():
    src = INIT_SH.read_text()
    # Legacy /vault/data/{root-token,init-keys.json} are removed from the app path.
    assert 'rm -f "/vault/data/$_legacy"' in src
    assert (
        "init-keys.json root-token" in src
        or "for _legacy in init-keys.json root-token" in src
    )


def test_scoped_backend_token_stays_app_readable():
    # The scoped service token (not root) is what backend consumes, and it stays
    # in the app-mounted runtime path.
    src = INIT_SH.read_text()
    assert "/vault/data/backend-token" in src


def test_public_cert_material_paths_unchanged():
    # Public/cert material stays in /vault/data so backend/broker keep working.
    src = INIT_SH.read_text()
    assert "/vault/data/ssh-ca-public-key" in src
    assert "/vault/data/agent-ca-cert.pem" in src
    assert "/vault/data/broker" in src
