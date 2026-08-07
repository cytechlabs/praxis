"""PRA-242: the production agent-broker must not inherit the base dev service.

Regression guard proving the production overlay explicitly overrides the broker
so a 1.0 production deploy does NOT run from backend/Dockerfile.dev, a bind-mounted
source checkout, or a bind-mounted .env:

- ``docker-compose.prod.yml`` defines an ``agent-broker`` override that uses the
  pinned production backend image + Dockerfile.prod and ``python -m app.broker.main``;
- its ``volumes: !override`` keeps only ``vault_data:/vault/data:ro`` (no
  ``./backend:/app``, no ``./backend/.env``, no ``vault_recovery``);
- the base broker publishes only the public tunnel port 8443, not the internal
  HTTP port 8444.

The source compose files are parsed with a small indent-based reader (no PyYAML,
which is absent from the backend/CI image). A bonus rendered-config check runs
when ``docker compose`` is available and skips otherwise.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_PROD = REPO / "docker-compose.prod.yml"

if not COMPOSE.exists() or not COMPOSE_PROD.exists():  # pragma: no cover - layout
    pytest.skip(
        "compose files not available (repo root missing)", allow_module_level=True
    )

PROD_IMAGE = "ghcr.io/cytechlabs/praxis-backend:${PRAXIS_VERSION:-latest}"


def _service_block(text: str, name: str) -> str:
    """Lines of a 2-space-indented compose service block, up to the next service
    header or the next top-level section."""
    import re

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


def _service_code(text: str, name: str) -> str:
    """Service block with comment lines stripped, so assertions test the actual
    config (an explanatory `# ... vault_recovery ...` comment must not count)."""
    block = _service_block(text, name)
    return "\n".join(ln for ln in block.splitlines() if not ln.lstrip().startswith("#"))


# --------------------------------------------------- prod override (source)


def test_prod_defines_agent_broker_override():
    # Regression guard: if the override is removed, the broker regresses to the
    # base dev service and this block is empty.
    block = _service_block(COMPOSE_PROD.read_text(), "agent-broker")
    assert block.strip(), "docker-compose.prod.yml must define an agent-broker override"


def test_prod_broker_uses_production_image_not_dockerfile_dev():
    block = _service_code(COMPOSE_PROD.read_text(), "agent-broker")
    assert (
        PROD_IMAGE in block
    ), "prod broker must use the pinned production backend image"
    assert "Dockerfile.prod" in block, "prod broker must build from Dockerfile.prod"
    assert (
        "Dockerfile.dev" not in block
    ), "prod broker must NOT reference Dockerfile.dev"
    assert "app.broker.main" in block, "prod broker must keep the broker command"


def test_prod_broker_volumes_drop_dev_mounts():
    block = _service_code(COMPOSE_PROD.read_text(), "agent-broker")
    # Dev bind mounts removed via !override.
    assert "!override" in block, "prod broker volumes must use !override"
    assert "vault_data:/vault/data:ro" in block, "prod broker must keep vault_data:ro"
    assert (
        "./backend:/app" not in block
    ), "prod broker must NOT bind-mount the source tree"
    assert "./backend/.env" not in block, "prod broker must NOT bind-mount .env"
    # PRA-241 recovery material stays Vault-only.
    assert "vault_recovery" not in block
    assert "/vault/recovery" not in block


def test_base_broker_does_not_publish_internal_http_port():
    # Ports are inherited from the base broker; only the public tunnel port is
    # published, never the internal 8444 HTTP API.
    block = _service_code(COMPOSE.read_text(), "agent-broker")
    assert (
        "8443:8443" in block or ":8443" in block
    ), "public tunnel port 8443 must be published"
    assert ":8444" not in block, "internal broker HTTP port 8444 must NOT be published"


def test_prod_broker_shares_the_backend_production_image():
    text = COMPOSE_PROD.read_text()
    backend = _service_code(text, "backend")
    broker = _service_code(text, "agent-broker")
    assert (
        PROD_IMAGE in backend and PROD_IMAGE in broker
    ), "prod broker should reuse the backend production image artifact"


# --------------------------------------------------- rendered config (bonus)


def test_rendered_prod_config_has_no_dev_broker():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    env = dict(os.environ)
    # The base compose marks SECRET_KEY as required (${SECRET_KEY:?...}); provide
    # one so `config` renders (CI's backend lane sets a real value already).
    env.setdefault("SECRET_KEY", "test-secret")
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "-f",
                str(COMPOSE_PROD),
                "--profile",
                "bundled",
                "config",
            ],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        pytest.skip("docker compose config not runnable here")
    if proc.returncode != 0:  # pragma: no cover - env/plugin unavailable
        pytest.skip(f"docker compose config failed: {proc.stderr[:200]}")

    rendered = proc.stdout
    # No service in the rendered prod config uses the dev Dockerfile.
    assert (
        "Dockerfile.dev" not in rendered
    ), "rendered prod config must not reference Dockerfile.dev"
    # The broker is present and points at the production image.
    assert "ghcr.io/cytechlabs/praxis-backend" in rendered
