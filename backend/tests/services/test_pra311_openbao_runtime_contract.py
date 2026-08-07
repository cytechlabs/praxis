"""PRA-311 Slice 2: bundled-secrets runtime is OpenBao, not HashiCorp Vault.

Lightweight, CI-runnable source/runtime contract (no Docker). Asserts:

- no SHIPPED Compose file uses a `hashicorp/vault` image;
- the bundled `vault` service pins an `openbao/openbao:` image;
- the bundled scripts drive the `bao` CLI, not the `vault` binary (so we do not
  rely on OpenBao's `vault`->`bao` shim);
- the compatibility contracts kept from Slice 1 (service name `vault`,
  VAULT_ADDR/VAULT_TOKEN, /vault paths, volume names) are still present.

The heavy existing-volume upgrade proof lives in
``scripts/test-openbao-upgrade-smoke.sh`` (Docker-based, run locally).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]

# Every Compose file we ship in the repo (base + prod overlay + the fresh-install
# smoke override, which is committed and therefore must not reintroduce the old image).
SHIPPED_COMPOSE = [
    REPO / "docker-compose.yml",
    REPO / "docker-compose.prod.yml",
    REPO / "scripts" / "fresh-install-smoke.override.yml",
]

VAULT_SCRIPTS = sorted((REPO / "vault" / "scripts").glob("*.sh"))

# The bundled-runtime CLI verbs. `vault <verb>` in a script would mean relying on
# OpenBao's compat shim instead of the native `bao` CLI.
_CLI_VERBS = r"(server|status|operator|login|secrets|write|read|policy|token)"
_VAULT_CLI = re.compile(rf"\bvault {_CLI_VERBS}\b")
_BAO_CLI = re.compile(rf"\bbao {_CLI_VERBS}\b")


def _strip_comments(text: str) -> str:
    """Drop `#` comments so explanatory prose mentioning hashicorp/vault does not
    trip the image assertions. Handles full-line and inline comments."""
    out = []
    for line in text.splitlines():
        hexpos = line.find("#")
        out.append(line if hexpos < 0 else line[:hexpos])
    return "\n".join(out)


def _image_lines(compose_text: str) -> list[str]:
    return [
        m.group(1)
        for m in re.finditer(r"^\s*image:\s*(\S+)", compose_text, re.MULTILINE)
    ]


@pytest.mark.parametrize("path", SHIPPED_COMPOSE, ids=lambda p: p.name)
def test_no_shipped_compose_uses_hashicorp_vault(path: Path):
    if not path.exists():  # pragma: no cover - layout guard
        pytest.skip(f"{path} not found")
    body = _strip_comments(path.read_text())
    # No image directive may reference the old HashiCorp Vault image.
    for img in _image_lines(body):
        assert "hashicorp/vault" not in img, f"{path.name} still pins {img}"
    # Belt-and-suspenders: the string must not survive anywhere outside comments.
    assert "hashicorp/vault" not in body, f"{path.name} references hashicorp/vault"


def test_bundled_vault_service_pins_openbao():
    body = (REPO / "docker-compose.yml").read_text()
    imgs = _image_lines(_strip_comments(body))
    openbao = [i for i in imgs if i.startswith("openbao/openbao:")]
    assert openbao, "docker-compose.yml must pin an openbao/openbao: image"


def test_bundled_scripts_use_bao_not_vault_cli():
    assert VAULT_SCRIPTS, "no vault/scripts/*.sh found"
    for script in VAULT_SCRIPTS:
        text = script.read_text()
        offenders = _VAULT_CLI.findall(text)
        assert not offenders, (
            f"{script.name} invokes the `vault` CLI {offenders}; bundled scripts must "
            f"use `bao` and not rely on OpenBao's vault shim"
        )
    # And at least the provisioner + entrypoint must actually drive `bao`.
    combined = "\n".join(s.read_text() for s in VAULT_SCRIPTS)
    assert _BAO_CLI.search(combined), "expected `bao` CLI usage in the bundled scripts"


def test_compatibility_contracts_preserved():
    """Slice-1 compatibility names must remain (no rename in this slice)."""
    base = (REPO / "docker-compose.yml").read_text()
    # Docker service name and env compatibility.
    assert re.search(
        r"^\s{2}vault:", base, re.MULTILINE
    ), "service name `vault` must remain"
    assert "VAULT_ADDR" in base and "VAULT_TOKEN" in base
    # Runtime + recovery mounts and volume names.
    assert "/vault/data" in base and "/vault/recovery" in base
    assert "vault_data" in base and "vault_recovery" in base


def test_healthcheck_uses_bao():
    base = (REPO / "docker-compose.yml").read_text()
    # The bundled vault service healthcheck should probe via `bao`, not `vault`.
    assert re.search(
        r'test:\s*\[\s*"CMD"\s*,\s*"bao"\s*,\s*"status"\s*\]', base
    ), "vault healthcheck should use `bao status`"
