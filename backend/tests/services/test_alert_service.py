"""Tests for PRA-125 webhook delivery hardening."""

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from unittest.mock import patch

from app.db.models import AlertConfig, AlertHistory
from app.services import alert_service


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeGuardPost:
    """Stand-in for ``outbound_http_guard.post`` — records the delivery call and
    returns a canned response (or raises). Bypasses real DNS + sockets; the
    guard's own validation / pinning / redirect behavior is covered end-to-end in
    ``test_pra365_outbound_ssrf_guard``. These tests exercise ``alert_service``'s
    orchestration (signing, status handling, retry scheduling)."""

    def __init__(self, resp=None, raise_exc=None):
        self._resp = resp or _FakeResponse()
        self._raise = raise_exc
        self.calls = []

    def __call__(self, url, *, content=None, headers=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "content": content, "headers": headers or {}})
        if self._raise:
            raise self._raise
        return self._resp


# -- sign_payload -----------------------------------------------------------


def test_sign_payload_matches_hmac():
    body = b'{"event_type":"test"}'
    secret = "shhh"
    sig = alert_service.sign_payload(secret, body)
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == expected


# -- _post ------------------------------------------------------------------


def test_post_adds_signature_header_when_secret_set():
    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        status, err = alert_service._post("http://h.example/hook", b"{}", secret="abc")
    assert status == 200
    assert err is None
    assert fake.calls[0]["headers"]["X-Praxis-Signature"].startswith("sha256=")


def test_post_omits_signature_header_without_secret():
    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        alert_service._post("http://h.example/hook", b"{}", secret=None)
    assert "X-Praxis-Signature" not in fake.calls[0]["headers"]


def test_post_returns_error_on_4xx():
    fake = _FakeGuardPost(_FakeResponse(500, text="boom"))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        status, err = alert_service._post("http://h/", b"{}", None)
    assert status == 500
    assert "HTTP 500" in err
    # The target's response body is never surfaced into the error string (it can
    # leak internal-service bytes into alert history).
    assert "boom" not in err


def test_post_reports_blocked_ssrf_target():
    fake = _FakeGuardPost(
        raise_exc=alert_service.outbound_http_guard.SsrfBlocked("nope")
    )
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        status, err = alert_service._post("http://169.254.169.254/", b"{}", None)
    assert status == 0
    assert "Blocked outbound target" in err


def test_post_maps_timeout_to_bounded_error():
    import httpx

    fake = _FakeGuardPost(raise_exc=httpx.TimeoutException("slow"))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        status, err = alert_service._post("http://h/", b"{}", None)
    assert status == 0
    assert "Timeout" in err


# -- _schedule_retry (backoff math) -----------------------------------------


def test_schedule_retry_uses_backoff_table():
    row = AlertHistory(attempt_count=1)
    alert_service._schedule_retry(row)
    assert row.status == "failed"
    delta = (row.next_retry_at - datetime.utcnow()).total_seconds()
    # 30s ±5s slack
    assert 25 <= delta <= 35


def test_schedule_retry_dead_letters_after_max():
    row = AlertHistory(attempt_count=alert_service.MAX_ATTEMPTS)
    alert_service._schedule_retry(row)
    assert row.status == "dead_letter"
    assert row.next_retry_at is None


# -- payload formatter ------------------------------------------------------


def test_build_payload_slack_has_blocks():
    cfg = AlertConfig(alert_type="slack")
    payload = alert_service._build_payload(cfg, "job_failed", "t", "m", "error")
    assert "attachments" in payload
    assert payload["attachments"][0]["color"] == alert_service.SEVERITY_COLORS["error"]


def test_build_payload_generic_shape():
    cfg = AlertConfig(alert_type="webhook")
    payload = alert_service._build_payload(cfg, "job_ok", "t", "m", "info")
    assert payload["event_type"] == "job_ok"
    assert payload["severity"] == "info"
    assert "timestamp" in payload


# -- send_alert end-to-end (in-memory DB) -----------------------------------


def _mk_config(db, **overrides):
    cfg = AlertConfig(
        name="t",
        alert_type="webhook",
        destination="http://example.test/hook",
        events=json.dumps(["job_failed"]),
        enabled=True,
        **overrides,
    )
    db.add(cfg)
    db.flush()
    return cfg


def test_send_alert_marks_row_sent_on_success(db):
    cfg = _mk_config(db)
    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        alert_service.send_alert(db, "job_failed", "title", "msg", "error")
    row = db.query(AlertHistory).filter_by(alert_config_id=cfg.id).one()
    assert row.status == "sent"
    assert row.response_code == 200
    assert row.attempt_count == 1


def test_send_alert_schedules_retry_on_failure(db):
    cfg = _mk_config(db)
    fake = _FakeGuardPost(_FakeResponse(500, text="boom"))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        alert_service.send_alert(db, "job_failed", "t", "m", "error")
    row = db.query(AlertHistory).filter_by(alert_config_id=cfg.id).one()
    assert row.status == "failed"
    assert row.next_retry_at is not None
    assert row.error_message and "HTTP 500" in row.error_message


def test_send_alert_skips_unsubscribed_event(db):
    _mk_config(db)  # events=[job_failed]
    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        alert_service.send_alert(db, "something_else", "t", "m", "info")
    assert db.query(AlertHistory).count() == 0


# -- retry_pending_deliveries ----------------------------------------------


def test_retry_pending_picks_due_rows(db):
    cfg = _mk_config(db)
    row = AlertHistory(
        alert_config_id=cfg.id,
        event_type="job_failed",
        message="x",
        sent_at=datetime.utcnow(),
        status="failed",
        payload=json.dumps({"x": 1}),
        attempt_count=1,
        next_retry_at=datetime.utcnow() - timedelta(seconds=1),
    )
    db.add(row)
    db.flush()

    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        processed = alert_service.retry_pending_deliveries(db)
    assert processed == 1
    db.refresh(row)
    assert row.status == "sent"
    assert row.attempt_count == 2


def test_retry_pending_skips_future_rows(db):
    cfg = _mk_config(db)
    row = AlertHistory(
        alert_config_id=cfg.id,
        event_type="job_failed",
        message="x",
        sent_at=datetime.utcnow(),
        status="failed",
        payload=json.dumps({"x": 1}),
        attempt_count=1,
        next_retry_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.add(row)
    db.flush()

    fake = _FakeGuardPost(_FakeResponse(200))
    with patch.object(alert_service.outbound_http_guard, "post", fake):
        processed = alert_service.retry_pending_deliveries(db)
    assert processed == 0
