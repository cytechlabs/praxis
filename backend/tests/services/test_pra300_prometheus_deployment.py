"""PRA-300: the bundled Prometheus deployment is durable, current, and locked down.

Source-Compose regression guards (no PyYAML — it is absent from the backend/CI
image, so the files are read as text) that the bundled infrastructure-telemetry
Prometheus stays: pinned to a current image, loopback-only, backend-net-only,
scraping ``backend:9090``, persisting its TSDB to a named volume, health-checked on
readiness, and never publicly exposed by the prod overlay. Also validates the minimal
``prometheus.yml`` scrape contract (one target, no rules/alerting).
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_PROD = REPO / "docker-compose.prod.yml"
PROM_YML = REPO / "prometheus.yml"

if not (COMPOSE.exists() and COMPOSE_PROD.exists() and PROM_YML.exists()):
    pytest.skip("compose/prometheus files not available", allow_module_level=True)


def _service_block(text: str, name: str) -> str:
    """Return the indented body of a top-level Compose service, as text."""
    header = re.compile(rf"^  {re.escape(name)}:\s*$")
    out: list[str] = []
    in_block = False
    for ln in text.splitlines():
        if not in_block:
            if header.match(ln):
                in_block = True
            continue
        # A new top-level (2-space) service/key or a 0-indent block ends this one.
        if re.match(r"^  \S", ln) or (
            ln and not ln.startswith(" ") and ln.rstrip().endswith(":")
        ):
            break
        out.append(ln)
    return "\n".join(out)


@pytest.fixture(scope="module")
def prom_block():
    return _service_block(COMPOSE.read_text(), "prometheus")


# ------------------------------------------------------------- image pinning

# Current-LTS floor for the bundled Prometheus. The 3.5 LTS line ends upstream
# support on 2026-07-31; 3.13.x is the current LTS. This is a deterministic proxy for
# "not near-EOL" — bump the floor when the LTS line advances. It catches a regression
# to 3.5.x (near-EOL) or 2.51.x (old), not just "any v3".
_MIN_PROMETHEUS = (3, 13)


def test_prometheus_image_is_pinned_and_current(prom_block):
    # Must be a concrete vX.Y.Z pin — this alone rules out `latest`/floating tags.
    m = re.search(r"image:\s*prom/prometheus:v(\d+)\.(\d+)\.(\d+)\b", prom_block)
    assert m, "prometheus image must be pinned to a concrete prom/prometheus:vX.Y.Z tag"
    major, minor, _patch = (int(g) for g in m.groups())
    assert (major, minor) >= _MIN_PROMETHEUS, (
        f"Prometheus pin v{major}.{minor}.x is below the required current-LTS floor "
        f"v{_MIN_PROMETHEUS[0]}.{_MIN_PROMETHEUS[1]}.x (near-EOL / stale) — bump it."
    )


# ----------------------------------------------------------- loopback-only UI


def test_prometheus_ui_is_loopback_only(prom_block):
    assert "127.0.0.1:9091:9090" in prom_block
    # No all-interfaces publish of the UI.
    assert "0.0.0.0:9091" not in prom_block
    assert not re.search(
        r'^\s*-\s*"?9091:9090', prom_block, re.MULTILINE
    ), "Prometheus UI must bind 127.0.0.1 only, never all interfaces"


# --------------------------------------------------------- network isolation


def test_prometheus_only_on_backend_net(prom_block):
    assert "backend_net" in prom_block
    assert (
        "frontend_net" not in prom_block
    ), "Prometheus must stay isolated on backend_net (no frontend reachability)"


# ----------------------------------------------------------- TSDB persistence


def test_prometheus_tsdb_uses_named_volume(prom_block):
    assert "prometheus_data:/prometheus" in prom_block
    # The named volume is declared at the top level (not an anonymous/bind mount).
    volumes_section = COMPOSE.read_text().split("\nvolumes:", 1)[-1]
    assert re.search(
        r"^\s{2}prometheus_data:\s*$", volumes_section, re.MULTILINE
    ), "prometheus_data must be a declared named volume"


# --------------------------------------------------------- readiness health


def test_prometheus_healthcheck_uses_readiness(prom_block):
    assert "healthcheck:" in prom_block
    assert "/-/ready" in prom_block, "healthcheck must probe Prometheus readiness"


def test_prometheus_waits_for_backend_health(prom_block):
    # Health-aware startup: do not scrape before the exporter can serve.
    assert "condition: service_healthy" in prom_block


# ----------------------------------------------------- prod overlay is not public


def test_prod_overlay_does_not_publish_prometheus(prom_block):
    prod_block = _service_block(COMPOSE_PROD.read_text(), "prometheus")
    # The prod overlay must not introduce a public host binding for Prometheus.
    assert "0.0.0.0" not in prod_block
    if "ports:" in prod_block:  # if it ever overrides ports, they stay loopback
        assert "127.0.0.1" in prod_block


# ------------------------------------------------------ prometheus.yml contract


def test_prometheus_config_is_minimal_and_targets_backend():
    text = PROM_YML.read_text()
    assert "backend:9090" in text, "scrape target must be backend:9090"
    assert "job_name" in text
    # 1.0 ships no Alertmanager / recording+alert rules.
    assert "rule_files" not in text
    assert "alerting" not in text
    assert "alertmanager" not in text.lower()
