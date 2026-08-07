"""PRA-365: alert webhook SSRF rejection at the API boundary.

Complements the guard unit tests (``test_pra365_outbound_ssrf_guard``) by
exercising the ``/alerts`` create/update routes end-to-end: literal and
DNS-resolved disallowed destinations are rejected, allowed public targets pass,
and the alert path does NOT inherit the audit-sink private-target override.
"""

import socket

import pytest

# The alert destination guard resolves DNS, so these fake public/private names
# are mapped through a getaddrinfo stub; literal IPs never hit DNS.
_REAL_GETADDRINFO = socket.getaddrinfo
_NAMES = {
    "good.webhook.test": "93.184.216.34",  # public
    "evil.webhook.test": "10.0.0.5",  # resolves into RFC1918
}


def _fake_getaddrinfo(host, *args, **kwargs):
    if host in _NAMES:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_NAMES[host], 0))]
    return _REAL_GETADDRINFO(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def _patch_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


def _create(client, destination, name="pra365-alert"):
    return client.post(
        "/alerts",
        json={
            "name": name,
            "alert_type": "webhook",
            "destination": destination,
            "events": ["job_failed"],
        },
    )


# ── create rejection ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "destination",
    [
        "http://127.0.0.1/hook",  # loopback
        "http://169.254.169.254/hook",  # cloud metadata
        "http://10.0.0.5/hook",  # RFC1918 literal
        "https://[::1]/hook",  # IPv6 loopback
        "http://localhost/hook",  # local name
        "ftp://example.com/hook",  # bad scheme
    ],
)
def test_create_rejects_disallowed_literal(authed_client, destination):
    res = _create(authed_client, destination)
    assert res.status_code == 400, res.text


def test_create_rejects_dns_resolved_private(authed_client):
    # Name resolves into RFC1918 space -> blocked.
    res = _create(authed_client, "https://evil.webhook.test/hook")
    assert res.status_code == 400, res.text


def test_create_allows_public(authed_client):
    res = _create(authed_client, "https://good.webhook.test/hook")
    assert res.status_code == 200, res.text


# ── update rejection ───────────────────────────────────────────────────────


def test_update_rejects_disallowed_destination(authed_client):
    created = _create(
        authed_client, "https://good.webhook.test/hook", name="pra365-upd"
    )
    assert created.status_code == 200, created.text
    config_id = created.json()["config"]["id"]

    res = authed_client.put(
        f"/alerts/{config_id}", json={"destination": "http://127.0.0.1/hook"}
    )
    assert res.status_code == 400, res.text


# ── flag isolation: audit override must NOT open alert targets ──────────────


def test_create_rejects_private_even_with_audit_override(authed_client, monkeypatch):
    # The audit-sink escape hatch alone must not enable private alert targets.
    monkeypatch.setenv("AUDIT_SINK_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.delenv("ALERT_ALLOW_PRIVATE_TARGETS", raising=False)
    res = _create(authed_client, "http://10.0.0.5/hook", name="pra365-audit-flag")
    assert res.status_code == 400, res.text


def test_create_allows_private_with_dedicated_alert_flag(authed_client, monkeypatch):
    # The dedicated alert escape hatch does allow an internal collector.
    monkeypatch.setenv("ALERT_ALLOW_PRIVATE_TARGETS", "1")
    res = _create(authed_client, "http://10.0.0.5/hook", name="pra365-alert-flag")
    assert res.status_code == 200, res.text
