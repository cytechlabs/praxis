"""PRA-226 AUTH-05: production proxy-trust hardening.

The backend derives rate-limit identity (``app.core.rate_limit``) and every
audit ``actor_ip`` from the uvicorn-resolved ``request.client.host``. That value
is only trustworthy when uvicorn is told which proxies may set
``X-Forwarded-For``. These tests lock in:

  * the production entrypoint no longer trusts ``--forwarded-allow-ips='*'``,
    and instead reads an env-driven allow-list defaulting to loopback, and
  * the rate-limit key derives from the connection peer, not a spoofable
    ``X-Forwarded-For`` header the app reads itself.

AUTH-06 (production ``SECRET_KEY`` strength) is already covered by
``test_pra220_auth_hardening.py`` and is intentionally not duplicated here.
"""

from pathlib import Path

from slowapi.util import get_remote_address
from starlette.requests import Request

_START_PROD = Path(__file__).resolve().parents[2] / "scripts" / "start.prod.sh"


def _request(client, headers=None):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "client": client,  # (host, port) tuple, or None
    }
    return Request(scope)


def test_rate_limit_key_uses_connection_peer_not_forwarded_header():
    # A direct client must not be able to raise its rate-limit budget or forge
    # an audit IP by sending X-Forwarded-For; the key is the uvicorn-resolved
    # connection peer, which uvicorn only rewrites for a trusted proxy.
    req = _request(("10.0.0.5", 40000), {"x-forwarded-for": "1.2.3.4"})
    assert get_remote_address(req) == "10.0.0.5"


def test_rate_limit_key_falls_back_when_no_client():
    assert get_remote_address(_request(None)) == "127.0.0.1"


def test_start_prod_does_not_trust_all_forwarded_ips():
    body = _START_PROD.read_text()
    assert "--forwarded-allow-ips='*'" not in body
    assert '--forwarded-allow-ips="*"' not in body


def test_start_prod_trusts_env_driven_proxies_defaulting_to_loopback():
    body = _START_PROD.read_text()
    assert "FORWARDED_ALLOW_IPS" in body
    assert "FORWARDED_ALLOW_IPS:-127.0.0.1" in body
