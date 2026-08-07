"""PRA-299: production-parity Compose contract.

Locks the production overlay's launch-critical guarantees so the dev-first
defaults can never silently regress the rendered production config:

- backend runs with ``ENVIRONMENT=production`` — the prod overlay forces it as a
  literal so it can never resolve to ``development`` (which would disable the
  production startup-hardening gates), even when the operator's environment or
  ``.env`` sets ``ENVIRONMENT=development``. Since PRA-299 the base stack also
  defaults to production rather than the retired dev default;
- the backend keeps all three persistent app volumes: ``recordings_data``,
  ``mirror_data``, and ``vault_data:ro``;
- the production overlay builds from the production Dockerfiles / pinned images
  and never references ``Dockerfile.dev``;
- backend + frontend publish no direct host app ports (Caddy is the sole browser
  ingress, opt-in via ``--profile proxy``);
- ``PRAXIS_VERSION`` pins the released image tags (release deploys must set it;
  the default is the unpinned ``latest``).

Source compose files are parsed with a small indent-based reader (no PyYAML in
the backend/CI image). Bonus rendered ``docker compose config`` checks run when
docker + PyYAML are available and skip otherwise — mirroring
``test_pra249_prod_backend_ingress`` / ``test_pra242_prod_broker_override``.
"""

import os
import re
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


def _service_block(text: str, name: str) -> str:
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
    """Service block with comment lines stripped so an explanatory comment can't
    satisfy (or trip) an assertion."""
    block = _service_block(text, name)
    return "\n".join(ln for ln in block.splitlines() if not ln.lstrip().startswith("#"))


# --------------------------------------------------- source assertions


def test_prod_backend_forces_environment_production():
    block = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert (
        "ENVIRONMENT=production" in block
    ), "prod backend must force ENVIRONMENT=production (literal, not a default)"
    # It must be a literal, not an interpolation that could fall back to dev.
    assert (
        "ENVIRONMENT=${ENVIRONMENT" not in block
    ), "prod backend ENVIRONMENT must not be an interpolated default"


def test_base_backend_is_production_parity():
    # PRA-299: the base stack is production-parity — it builds Dockerfile.prod (no
    # dev image / source bind mount) and defaults ENVIRONMENT to production, not
    # the retired dev default. The prod overlay still forces production as a
    # literal on top.
    block = _service_code(COMPOSE.read_text(), "backend")
    assert "Dockerfile.prod" in block, "base backend must build the production image"
    assert (
        "Dockerfile.dev" not in block
    ), "base backend must not reference Dockerfile.dev"
    assert (
        "ENVIRONMENT=${ENVIRONMENT:-development}" not in block
    ), "base backend must not default ENVIRONMENT to development"
    assert (
        "./backend:/app" not in block
    ), "base backend must not bind-mount the source tree"


def test_prod_backend_keeps_all_persistent_volumes():
    block = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert "volumes: !override" in block, "prod backend must use volumes: !override"
    assert (
        "recordings_data:/data/praxis/recordings" in block
    ), "prod backend must persist session recordings"
    assert (
        "mirror_data:/data/praxis/mirrors" in block
    ), "prod backend must persist mirrored content"
    assert (
        "vault_data:/vault/data:ro" in block
    ), "prod backend must keep the read-only Vault data mount"


def test_prod_backend_uses_production_dockerfile_not_dev():
    block = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert "Dockerfile.prod" in block, "prod backend must build from Dockerfile.prod"
    assert (
        "Dockerfile.dev" not in block
    ), "prod backend must not reference Dockerfile.dev"
    assert (
        "ghcr.io/cytechlabs/praxis-backend:${PRAXIS_VERSION:-latest}" in block
    ), "prod backend must reference the pinned/tagged production image"


def test_prod_backend_and_frontend_clear_host_ports():
    for name in ("backend", "frontend"):
        block = _service_code(COMPOSE_PROD.read_text(), name)
        assert (
            "ports: !override []" in block
        ), f"prod {name} must clear direct host ports (browser ingress is via proxy)"


def test_prod_proxy_is_browser_ingress():
    # Caddy is the intentional, opt-in browser ingress under --profile proxy.
    prod = COMPOSE_PROD.read_text()
    caddy = _service_code(prod, "caddy")
    assert "profiles: [proxy]" in caddy, "Caddy must be gated behind the proxy profile"
    assert '"80:80"' in caddy and '"443:443"' in caddy


def test_prod_images_are_version_pinnable():
    # Both released images key off PRAXIS_VERSION so a release deploy can pin a tag
    # (the rendered-config test below proves a set value is honored).
    prod = COMPOSE_PROD.read_text()
    for name in ("backend", "frontend"):
        block = _service_code(prod, name)
        assert (
            "${PRAXIS_VERSION:-latest}" in block
        ), f"prod {name} image tag must be driven by PRAXIS_VERSION"


# --------------------------------------------------- rendered config (bonus)


def _render_prod_config(extra_env=None):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    yaml = pytest.importorskip("yaml")
    env = dict(os.environ)
    env.setdefault("SECRET_KEY", "test-secret")
    env.setdefault("POSTGRES_PASSWORD", "test-pg")
    if extra_env:
        env.update(extra_env)
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
                "--profile",
                "proxy",
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
    if proc.returncode != 0:  # pragma: no cover - plugin/env unavailable
        pytest.skip(f"docker compose config failed: {proc.stderr[:200]}")
    return yaml.safe_load(proc.stdout)


def _backend_env(services):
    env = services["backend"].get("environment") or {}
    if isinstance(env, list):  # normalize "K=V" list form
        env = dict(e.split("=", 1) for e in env if "=" in e)
    return env


def test_rendered_prod_backend_is_production_even_when_env_says_development():
    # The prod overlay must WIN over a hostile/stale ENVIRONMENT=development.
    services = _render_prod_config({"ENVIRONMENT": "development"})["services"]
    assert (
        _backend_env(services).get("ENVIRONMENT") == "production"
    ), "prod overlay must force ENVIRONMENT=production regardless of the host env"


def test_rendered_prod_backend_keeps_recordings_volume():
    services = _render_prod_config()["services"]
    targets = {v.get("target") for v in (services["backend"].get("volumes") or [])}
    assert "/data/praxis/recordings" in targets, f"recordings volume missing: {targets}"
    assert "/data/praxis/mirrors" in targets
    assert "/vault/data" in targets


def test_rendered_prod_has_no_dockerfile_dev():
    # Render as raw text and assert the dev Dockerfile never appears.
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    pytest.importorskip("yaml")
    env = dict(os.environ)
    env.setdefault("SECRET_KEY", "test-secret")
    env.setdefault("POSTGRES_PASSWORD", "test-pg")
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
            "--profile",
            "proxy",
            "config",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    if proc.returncode != 0:  # pragma: no cover
        pytest.skip(f"docker compose config failed: {proc.stderr[:200]}")
    assert "Dockerfile.dev" not in proc.stdout


def test_rendered_praxis_version_pins_image_tags():
    services = _render_prod_config({"PRAXIS_VERSION": "v9.9.9-test"})["services"]
    for name in ("backend", "frontend", "agent-broker"):
        image = services[name].get("image", "")
        assert image.endswith(
            ":v9.9.9-test"
        ), f"{name} image not pinned to PRAXIS_VERSION: {image!r}"
