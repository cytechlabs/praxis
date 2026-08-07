"""PRA-313 follow-up: transport circuit-breaker tunables in Connection Settings API.

The two new ``global_connection_settings`` breaker knobs added by PRA-313
(``transport_failure_threshold`` / ``transport_cooldown_seconds``) must be
readable and writable through the existing admin Connection Settings surface,
with their documented validation ranges enforced.
"""

from __future__ import annotations


def _valid_payload(**overrides):
    body = {
        "connection_timeout": 10,
        "max_pool_size": 50,
        "pool_cleanup_interval": 300,
        "max_idle_time": 600,
        "unreachable_threshold": 2,
        "default_ssh_port": 22,
        "transport_failure_threshold": 3,
        "transport_cooldown_seconds": 60,
    }
    body.update(overrides)
    return body


def test_get_returns_transport_breaker_defaults(authed_client):
    res = authed_client.get("/connection-settings")
    assert res.status_code == 200, res.text
    data = res.json()
    # New fields are present with the PRA-313 defaults.
    assert data["transport_failure_threshold"] == 3
    assert data["transport_cooldown_seconds"] == 60


def test_put_persists_transport_breaker_values(authed_client):
    res = authed_client.put(
        "/connection-settings",
        json=_valid_payload(
            transport_failure_threshold=5, transport_cooldown_seconds=120
        ),
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["transport_failure_threshold"] == 5
    assert data["transport_cooldown_seconds"] == 120

    # Round-trips on a subsequent GET.
    got = authed_client.get("/connection-settings").json()
    assert got["transport_failure_threshold"] == 5
    assert got["transport_cooldown_seconds"] == 120


def test_put_accepts_range_bounds(authed_client):
    """Both ends of each documented range are accepted."""
    res = authed_client.put(
        "/connection-settings",
        json=_valid_payload(
            transport_failure_threshold=1, transport_cooldown_seconds=5
        ),
    )
    assert res.status_code == 200, res.text
    res = authed_client.put(
        "/connection-settings",
        json=_valid_payload(
            transport_failure_threshold=20, transport_cooldown_seconds=3600
        ),
    )
    assert res.status_code == 200, res.text


def test_put_rejects_threshold_out_of_range(authed_client):
    # 0 is below the 1-20 range.
    res = authed_client.put(
        "/connection-settings", json=_valid_payload(transport_failure_threshold=0)
    )
    assert res.status_code == 422, res.text
    # 21 is above it.
    res = authed_client.put(
        "/connection-settings", json=_valid_payload(transport_failure_threshold=21)
    )
    assert res.status_code == 422, res.text


def test_put_rejects_cooldown_out_of_range(authed_client):
    # 4 is below the 5-3600 range.
    res = authed_client.put(
        "/connection-settings", json=_valid_payload(transport_cooldown_seconds=4)
    )
    assert res.status_code == 422, res.text
    # 3601 is above it.
    res = authed_client.put(
        "/connection-settings", json=_valid_payload(transport_cooldown_seconds=3601)
    )
    assert res.status_code == 422, res.text
