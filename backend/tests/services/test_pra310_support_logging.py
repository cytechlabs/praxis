"""PRA-310: structured supportability log lines drop unsafe fields."""

from __future__ import annotations

import logging

from app.core.support_logging import log_support_event


def test_emits_event_with_safe_fields(caplog):
    with caplog.at_level(logging.INFO):
        log_support_event(
            logging.getLogger("pra310.support"),
            "auth.login",
            outcome="success",
            actor_user_id=7,
            system_id=None,  # None values are omitted
        )
    line = caplog.records[-1].getMessage()
    assert "event=auth.login" in line
    assert "actor_user_id=7" in line
    assert "outcome=success" in line
    assert "system_id" not in line  # None dropped


def test_drops_unknown_and_unsafe_fields(caplog):
    with caplog.at_level(logging.INFO):
        log_support_event(
            logging.getLogger("pra310.support"),
            "license.apply",
            license_instance_id="inst-123",
            password="hunter2",  # not on the safe list
            vault_token="hvs.abc",  # not on the safe list
        )
    line = caplog.records[-1].getMessage()
    assert "license_instance_id=inst-123" in line
    assert "hunter2" not in line
    assert "password" not in line
    assert "hvs.abc" not in line


def test_logging_never_raises():
    # A logger that blows up must not propagate out of the helper.
    class Boom(logging.Logger):
        def log(self, *a, **k):  # noqa: D401
            raise RuntimeError("boom")

    log_support_event(Boom("boom"), "host.enroll", system_id=1)
