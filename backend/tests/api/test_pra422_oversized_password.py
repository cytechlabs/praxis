"""PRA-422: an oversized password candidate is a failed comparison, not a fault.

Passlib refuses a candidate longer than ``MAX_PASSWORD_SIZE`` by raising
``PasswordSizeError`` from inside ``CryptContext.verify``, before it does any
comparison work. ``app.core.security.verify_password`` used to let that
propagate, so a password over the limit reached the public, unauthenticated
``POST /auth/login`` boundary as an unhandled exception and a 500 rather than
the sanitized authentication failure every other bad credential gets.

A candidate that large cannot match a stored hash, so the correct answer is
``False``. These tests pin that, pin that only this one exception is absorbed,
pin that nothing derived from the attempted password reaches the response or the
logs, and carry a control proving the exception is real so the regression tests
cannot pass vacuously.
"""

from __future__ import annotations

import logging

import pytest
from passlib.exc import PasswordSizeError
from passlib.utils import MAX_PASSWORD_SIZE

from app.core.auth import get_password_hash
from app.core.security import pwd_context, verify_password

# A marker the assertions can search for in responses and log records. Kept in
# the candidate so a leak of any prefix of it is detectable.
SENTINEL = "praxis-oversized-secret-marker"

KNOWN_PASSWORD = "testpass123"


def _oversized(length: int = MAX_PASSWORD_SIZE + 1) -> str:
    """A candidate one byte past what passlib will accept, carrying SENTINEL."""
    assert length > len(SENTINEL)
    return SENTINEL + "x" * (length - len(SENTINEL))


@pytest.fixture
def known_hash() -> str:
    return get_password_hash(KNOWN_PASSWORD)


# --------------------------------------------------------------------------
# Control: the exception these tests are about is real
# --------------------------------------------------------------------------


def test_pre_fix_verification_raises_the_specific_passlib_error(known_hash):
    """The superseded implementation was exactly this call, unguarded.

    Without this, every assertion below could pass on a passlib that had simply
    stopped raising, and the guard in ``verify_password`` would be dead code.
    """
    with pytest.raises(PasswordSizeError):
        pwd_context.verify(_oversized(), known_hash)


def test_the_absorbed_error_is_narrower_than_value_error():
    """``PasswordSizeError`` is a ``ValueError``, so the catch must name it.

    Catching ``ValueError`` here would swallow unrelated malformed-hash and
    unknown-scheme failures that must keep surfacing.
    """
    assert issubclass(PasswordSizeError, ValueError)
    assert PasswordSizeError is not ValueError


# --------------------------------------------------------------------------
# verify_password
# --------------------------------------------------------------------------


def test_oversized_candidate_is_a_failed_comparison(known_hash):
    assert verify_password(_oversized(), known_hash) is False


def test_candidate_at_the_limit_is_compared_rather_than_refused(known_hash):
    """The guard must not fire early.

    A candidate of exactly ``MAX_PASSWORD_SIZE`` is inside what passlib accepts,
    so it goes through a real comparison and comes back False on its merits.
    """
    at_limit = _oversized(MAX_PASSWORD_SIZE)
    assert len(at_limit) == MAX_PASSWORD_SIZE
    assert pwd_context.verify(at_limit, known_hash) is False
    assert verify_password(at_limit, known_hash) is False


def test_valid_password_still_verifies(known_hash):
    assert verify_password(KNOWN_PASSWORD, known_hash) is True


def test_ordinary_wrong_password_still_fails(known_hash):
    assert verify_password("not-the-password", known_hash) is False


def test_unrelated_verification_errors_still_propagate(monkeypatch, known_hash):
    """Only the size refusal is absorbed.

    A hash passlib cannot read is a real fault and must not be reported as a
    wrong password, which would hide a corrupted or truncated credential row.
    """

    def _raise_unrelated(*_args, **_kwargs):
        raise ValueError("hash could not be identified")

    monkeypatch.setattr(pwd_context, "verify", _raise_unrelated)
    with pytest.raises(ValueError, match="hash could not be identified"):
        verify_password(KNOWN_PASSWORD, known_hash)


# --------------------------------------------------------------------------
# POST /auth/login
# --------------------------------------------------------------------------


def test_login_with_an_oversized_password_matches_the_ordinary_failure(
    client, admin_user
):
    """Same status and same body as any other wrong password, never a 500."""
    ordinary = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "not-the-password"},
    )
    oversized = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": _oversized()},
    )

    assert ordinary.status_code == 401, ordinary.text
    assert oversized.status_code == 401, oversized.text
    assert oversized.json() == ordinary.json()
    assert "access_token" not in oversized.text


def test_login_with_an_oversized_password_still_succeeds_for_the_real_one(
    client, admin_user
):
    """The rejection above is about the candidate, not a poisoned login route."""
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": KNOWN_PASSWORD},
    )
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]


def test_login_with_an_oversized_password_leaks_nothing(client, admin_user, caplog):
    """No token, no traceback, no attempted password, no exception text."""
    with caplog.at_level(logging.DEBUG):
        res = client.post(
            "/auth/login",
            data={"username": admin_user.username, "password": _oversized()},
        )

    assert res.status_code == 401
    body = res.text
    for leak in (SENTINEL, "PasswordSizeError", "Traceback", "passlib", "maximum"):
        assert leak not in body, f"{leak!r} reached the response body"

    for record in caplog.records:
        message = record.getMessage()
        for leak in (SENTINEL, "PasswordSizeError", "passlib"):
            assert leak not in message, f"{leak!r} reached log record {record.name}"
        assert record.exc_info is None, f"{record.name} logged a traceback"
        assert record.exc_text is None


# --------------------------------------------------------------------------
# POST /auth/change-password
# --------------------------------------------------------------------------


def _change_password_body(current: str) -> dict:
    return {
        "current_password": current,
        "new_password": "a-new-password-1",
        "confirm_password": "a-new-password-1",
    }


def test_change_password_with_an_oversized_current_password_fails_normally(
    authed_client,
):
    """The authenticated path answers the same way as an ordinary wrong current."""
    ordinary = authed_client.post(
        "/auth/change-password", json=_change_password_body("not-the-password")
    )
    oversized = authed_client.post(
        "/auth/change-password", json=_change_password_body(_oversized())
    )

    assert ordinary.status_code == 400, ordinary.text
    assert oversized.status_code == 400, oversized.text
    assert oversized.json() == ordinary.json()
    assert SENTINEL not in oversized.text


def test_change_password_still_works_with_the_real_current_password(authed_client):
    """The guard must not have closed the path it protects."""
    res = authed_client.post(
        "/auth/change-password", json=_change_password_body(KNOWN_PASSWORD)
    )
    assert res.status_code == 200, res.text
