"""PRA-339: BrokerClient.logs() — fetch broker log records for the bundle.

Unlike ``health``, ``logs`` must NOT swallow HTTP errors: the diagnostics builder
relies on the distinction between a 404 (broker too old / unsupported) and a
network error (unavailable), so both must propagate.
"""

from __future__ import annotations

import httpx
import pytest

from app.services.broker_client import BrokerClient


def _client(handler) -> BrokerClient:
    return BrokerClient(
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://broker.test"
        )
    )


@pytest.mark.asyncio
async def test_logs_returns_body_on_200():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/logs"
        # Query params forwarded.
        assert request.url.params.get("limit") == "10"
        return httpx.Response(
            200,
            json={
                "installed": True,
                "records": [
                    {
                        "ts": 1.0,
                        "level": "INFO",
                        "logger": "app.broker.x",
                        "message": "m",
                    }
                ],
            },
        )

    bc = _client(handler)
    body = await bc.logs(limit=10, since_epoch=5.0)
    assert body["installed"] is True
    assert body["records"][0]["message"] == "m"


@pytest.mark.asyncio
async def test_logs_raises_on_500():
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with pytest.raises(httpx.HTTPStatusError):
        await _client(handler).logs()


@pytest.mark.asyncio
async def test_logs_raises_on_404():
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with pytest.raises(httpx.HTTPStatusError):
        await _client(handler).logs()
