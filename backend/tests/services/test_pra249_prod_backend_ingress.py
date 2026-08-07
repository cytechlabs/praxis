"""PRA-249: production Compose must not publish the backend/frontend host ports.

Regression guard proving a 1.0 production deploy cannot bypass Caddy/TLS via the
dev app host bindings:

- ``docker-compose.prod.yml`` clears the backend AND frontend host ports with
  ``ports: !override []``; both stay reachable only over the Docker networks;
- since PRA-299 the base stack is production-parity too — it no longer publishes
  ``8000:8000`` / ``3000:3000`` (the dev runtime that did was retired);
- in prod proxy mode the ONLY public (all-interfaces) host ports are Caddy
  ``80``/``443`` (HTTP ingress) and the agent-broker ``8443`` mTLS agent tunnel
  (a separate, client-cert-authenticated ingress, not an HTTP app bypass);
  loopback bindings such as Prometheus ``127.0.0.1:9091`` are non-public.

Source compose files are parsed with a small indent-based reader (no PyYAML,
absent from the backend/CI image). Bonus rendered ``docker compose config``
checks run when docker + PyYAML are available and skip otherwise.
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
    """Service block with comment lines stripped (an explanatory comment that
    mentions `8000:8000` must not count as a real port mapping)."""
    block = _service_block(text, name)
    return "\n".join(ln for ln in block.splitlines() if not ln.lstrip().startswith("#"))


# --------------------------------------------------- source assertions


def test_prod_backend_clears_host_ports():
    block = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert (
        "ports: !override []" in block
    ), "prod backend must clear host ports with `ports: !override []`"
    # No real port mapping publishes 8000 in the prod backend override.
    assert "8000:8000" not in block
    assert "0.0.0.0:8000" not in block


def test_base_backend_publishes_no_app_host_port():
    # PRA-299: the base stack is now production-parity — it no longer publishes a
    # direct backend app host port (the retired dev runtime bound 8000:8000).
    # Browser ingress is via Caddy (--profile proxy).
    block = _service_code(COMPOSE.read_text(), "backend")
    assert "8000:8000" not in block
    assert "0.0.0.0:8000" not in block


def test_prod_frontend_clears_host_ports():
    block = _service_code(COMPOSE_PROD.read_text(), "frontend")
    assert (
        "ports: !override []" in block
    ), "prod frontend must clear host ports with `ports: !override []`"
    assert "3000:3000" not in block


def test_base_frontend_publishes_no_app_host_port():
    # PRA-299: the base frontend no longer publishes 3000:3000 (retired dev
    # runtime); Caddy is the sole browser ingress.
    block = _service_code(COMPOSE.read_text(), "frontend")
    assert "3000:3000" not in block


def test_prod_backend_stays_on_docker_networks():
    # Backend must remain reachable internally (Caddy proxies to it; Prometheus
    # scrapes it) — the port clear must not detach it from the networks.
    block = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert "backend_net" in block
    assert "frontend_net" in block


def test_prod_caddy_publishes_80_and_443():
    block = _service_code(COMPOSE_PROD.read_text(), "caddy")
    assert '"80:80"' in block, "Caddy must publish 80 as the public ingress"
    assert '"443:443"' in block, "Caddy must publish 443 as the public ingress"


# --------------------------------------------------- rendered config (bonus)


# Loopback host IPs are not publicly reachable, so a `127.0.0.1:...` binding
# (e.g. Prometheus 9091) is treated as non-public.
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}

# The only host ports that may be published on ALL interfaces in production:
# Caddy's HTTP(S) ingress, and the agent-broker's mTLS agent-tunnel port (agents
# dial 8443; it is a separate, client-cert-authenticated ingress — not an HTTP
# app bypass of Caddy). Everything else must be unpublished or loopback-only.
_ALLOWED_PUBLIC = {("caddy", "80"), ("caddy", "443"), ("agent-broker", "8443")}


def _render_prod_config():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    yaml = pytest.importorskip("yaml")
    env = dict(os.environ)
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


def test_rendered_prod_backend_and_frontend_publish_no_host_ports():
    services = _render_prod_config()["services"]
    for name in ("backend", "frontend"):
        assert not services[name].get(
            "ports"
        ), f"prod {name} must publish no host ports, got {services[name].get('ports')}"


def test_rendered_prod_only_expected_public_ports():
    # In prod proxy mode, no service may publish a public (all-interfaces) host
    # port except Caddy 80/443 and the agent-broker 8443 mTLS tunnel. Loopback
    # bindings (Prometheus 9091) are allowed as non-public.
    services = _render_prod_config()["services"]
    for name, svc in services.items():
        for port in svc.get("ports") or []:
            published = str(port.get("published"))
            host_ip = str(port.get("host_ip") or "")
            if host_ip in _LOOPBACK:
                continue  # loopback binding — not publicly reachable
            assert (name, published) in _ALLOWED_PUBLIC, (
                f"{name} publishes a public host port {published} "
                f"(host_ip={host_ip or 'all-interfaces'}); only Caddy 80/443 and "
                f"the agent-broker 8443 mTLS tunnel may be public in production"
            )
    # And Caddy is present as the HTTP ingress.
    caddy_published = {
        str(p.get("published")) for p in (services.get("caddy", {}).get("ports") or [])
    }
    assert {
        "80",
        "443",
    } <= caddy_published, f"Caddy must publish 80 + 443, got {caddy_published}"


def test_rendered_prod_backend_stays_on_docker_networks():
    backend = _render_prod_config()["services"]["backend"]
    nets = backend.get("networks") or {}
    net_names = set(nets.keys()) if isinstance(nets, dict) else set(nets)
    assert {"backend_net", "frontend_net"} <= net_names
