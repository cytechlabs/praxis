"""Tests for PRA-143 audit event service + sink dispatcher."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from app.db.access_models import AuditSink, AuditSinkDelivery
from app.services import audit_event_service as aes

# ---------------------------------------------------------------- emit


def test_emit_persists_event_row(db, admin_user):
    row = aes.emit(
        db,
        action="session.open",
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="10.0.0.5",
        target_kind="system",
        target_id="1",
        context={"login": "alice"},
    )
    assert row.id is not None
    assert row.action == "session.open"
    assert row.outcome == "success"
    assert row.event_uuid
    # context round-trips cleanly
    assert json.loads(row.context_json) == {"login": "alice"}


def test_emit_rejects_non_dotted_action(db):
    with pytest.raises(aes.AuditError):
        aes.emit(db, action="login")


def test_event_to_dict_shape_is_stable(db, admin_user):
    row = aes.emit(
        db,
        action="command.exec",
        outcome="success",
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        target_kind="system",
        target_id="7",
        context={"command": "uname -a", "exit_code": 0},
    )
    d = aes.event_to_dict(row)
    assert d["schema_version"] == aes.SCHEMA_VERSION
    assert d["action"] == "command.exec"
    assert d["outcome"] == "success"
    assert d["actor"]["username"] == admin_user.username
    assert d["target"]["kind"] == "system"
    assert d["context"]["command"] == "uname -a"
    assert d["context"]["exit_code"] == 0
    assert d["event_uuid"] == row.event_uuid


def test_emit_enqueues_delivery_for_each_enabled_sink(db, admin_user):
    sink_a = AuditSink(
        name="a", kind="file", target="/tmp/a.jsonl", enabled=True, config_json="{}"
    )
    sink_b = AuditSink(
        name="b", kind="file", target="/tmp/b.jsonl", enabled=True, config_json="{}"
    )
    sink_disabled = AuditSink(
        name="c",
        kind="file",
        target="/tmp/c.jsonl",
        enabled=False,
        config_json="{}",
    )
    db.add_all([sink_a, sink_b, sink_disabled])
    db.commit()

    row = aes.emit(db, action="test.ping", actor_user_id=admin_user.id)

    deliveries = (
        db.query(AuditSinkDelivery).filter(AuditSinkDelivery.event_id == row.id).all()
    )
    assert {d.sink_id for d in deliveries} == {sink_a.id, sink_b.id}
    for d in deliveries:
        assert d.status == "pending"
        assert d.attempts == 0


# -------------------------------------------------------------- transports


def test_file_sink_appends_jsonl(tmp_path):
    sink = AuditSink(
        id=1,
        name="f",
        kind="file",
        target=str(tmp_path / "out.jsonl"),
        enabled=True,
        config_json="{}",
    )
    aes._send_file(sink, '{"event":1}')
    aes._send_file(sink, '{"event":2}')
    text = (tmp_path / "out.jsonl").read_text(encoding="utf-8")
    assert text == '{"event":1}\n{"event":2}\n'


def test_http_sink_signs_with_hmac():
    """Verify the HMAC header matches sha256 of the body keyed with secret."""
    import hashlib
    import hmac

    sink = AuditSink(
        id=1,
        name="h",
        kind="http",
        target="https://example.com/audit",
        hmac_secret="s3cr3t",
        config_json="{}",
        enabled=True,
    )
    captured = {}

    class _FakeResp:
        status_code = 200

    def _fake_post(url, *, content=None, headers=None, timeout=None, **kwargs):
        captured["url"] = url
        captured["content"] = content
        captured["headers"] = dict(headers or {})
        return _FakeResp()

    with patch.object(aes.outbound_http_guard, "post", _fake_post):
        aes._send_http(sink, '{"k":"v"}')

    sig = hmac.new(b"s3cr3t", b'{"k":"v"}', hashlib.sha256).hexdigest()
    assert captured["content"] == b'{"k":"v"}'
    assert captured["headers"].get("X-Praxis-Signature") == f"sha256={sig}"


# ---------------------------------------------------------- delivery flow


def test_deliver_one_marks_delivered_on_success(db, tmp_path):
    sink = AuditSink(
        name="s",
        kind="file",
        target=str(tmp_path / "x.jsonl"),
        enabled=True,
        config_json="{}",
    )
    db.add(sink)
    db.commit()

    event = aes.emit(db, action="test.ok")
    delivery = (
        db.query(AuditSinkDelivery)
        .filter(
            AuditSinkDelivery.sink_id == sink.id,
            AuditSinkDelivery.event_id == event.id,
        )
        .first()
    )
    aes._deliver_one(db, delivery)
    db.refresh(delivery)
    assert delivery.status == "delivered"
    assert delivery.delivered_at is not None


def test_deliver_one_retries_on_transport_error(db):
    """A transport raising OSError should schedule a retry, not die."""
    sink = AuditSink(
        name="s-bad",
        kind="file",
        target="/nonexistent-dir/xxx/out.jsonl",
        enabled=True,
        config_json="{}",
    )
    db.add(sink)
    db.commit()

    event = aes.emit(db, action="test.fail")
    delivery = (
        db.query(AuditSinkDelivery)
        .filter(AuditSinkDelivery.event_id == event.id)
        .first()
    )

    # Force the file-sink write to raise by swapping out the transport.
    def _boom(_sink, _payload):
        raise OSError("disk exploded")

    with patch.dict(aes._TRANSPORTS, {"file": _boom}):
        aes._deliver_one(db, delivery)
    db.refresh(delivery)
    assert delivery.status == "pending"
    assert delivery.attempts == 1
    assert delivery.next_attempt_at is not None
    assert "disk exploded" in (delivery.last_error or "")


def test_deliver_one_dead_letters_after_max_attempts(db):
    sink = AuditSink(
        name="s-dead",
        kind="file",
        target="/nonexistent/x.jsonl",
        enabled=True,
        config_json="{}",
    )
    db.add(sink)
    db.commit()
    event = aes.emit(db, action="test.doomed")
    delivery = (
        db.query(AuditSinkDelivery)
        .filter(AuditSinkDelivery.event_id == event.id)
        .first()
    )
    # Prime to one attempt below threshold
    delivery.attempts = aes.MAX_ATTEMPTS - 1
    db.commit()

    def _boom(_s, _p):
        raise OSError("nope")

    with patch.dict(aes._TRANSPORTS, {"file": _boom}):
        aes._deliver_one(db, delivery)
    db.refresh(delivery)
    assert delivery.status == "dead_letter"


def test_retry_dead_letter_resets(db):
    sink = AuditSink(
        name="s-retry",
        kind="file",
        target="/nonexistent/x.jsonl",
        enabled=True,
        config_json="{}",
    )
    db.add(sink)
    db.commit()
    event = aes.emit(db, action="test.retry")
    delivery = (
        db.query(AuditSinkDelivery)
        .filter(AuditSinkDelivery.event_id == event.id)
        .first()
    )
    delivery.status = "dead_letter"
    delivery.attempts = aes.MAX_ATTEMPTS
    delivery.last_error = "prior failure"
    db.commit()

    d2 = aes.retry_dead_letter(db, delivery.id)
    assert d2.status == "pending"
    assert d2.attempts == 0
    assert d2.last_error is None


def test_retry_rejects_non_dead_letter(db):
    sink = AuditSink(
        name="s-live", kind="file", target="/tmp/x", enabled=True, config_json="{}"
    )
    db.add(sink)
    db.commit()
    event = aes.emit(db, action="test.live")
    delivery = (
        db.query(AuditSinkDelivery)
        .filter(AuditSinkDelivery.event_id == event.id)
        .first()
    )
    # default is pending
    with pytest.raises(aes.AuditError):
        aes.retry_dead_letter(db, delivery.id)
