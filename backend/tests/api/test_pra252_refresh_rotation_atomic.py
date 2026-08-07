"""PRA-252: /auth/refresh rotation is atomic against concurrent replay.

The old flow read a valid ``RefreshToken`` row, minted new tokens, then flipped
the old row to invalid — a read-then-write race where two concurrent requests
could both observe the row as valid and both mint valid successors. The fix
claims the row with a single conditional ``UPDATE ... RETURNING`` before minting.

These tests prove the atomic-claim guarantee (the conditional UPDATE reports a
winner only when the row was still valid) and that a full refresh persists exactly
one valid successor with the old row invalidated. Concurrency is exercised with
two independent sessions on the shared test connection (the pattern in
``test_pra178_report_schedules.py::test_fire_due_concurrent_claim_only_one_run``):
the second claim sees the row already flipped and wins nothing — the same outcome
Postgres row-locking produces under true parallel connections.
"""

import threading
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import sessionmaker

from app.api.routes.auth import claim_refresh_token
from app.core.auth import get_password_hash
from app.db.models import RefreshToken, User


def _seed_valid_token(db, user_id, token="pra252-refresh-token"):
    db.add(
        RefreshToken(
            token=token,
            user_id=user_id,
            is_valid=True,
            expires_at=datetime.utcnow() + timedelta(days=7),
        )
    )
    db.commit()
    return token


def test_concurrent_claim_only_one_wins(db, admin_user):
    now = datetime.utcnow()
    token = _seed_valid_token(db, admin_user.id)

    # Two independent ORM sessions race the same atomic claim. Each commits its
    # claim (as a real request does) so the second session observes the first's
    # invalidation and wins nothing. A `None` return is the loser, which the route
    # maps to the existing 401.
    Session = sessionmaker(bind=db.bind, autoflush=False, expire_on_commit=False)
    session_a = Session()
    session_b = Session()
    try:
        claim_a = claim_refresh_token(session_a, token, now)
        session_a.commit()
        claim_b = claim_refresh_token(session_b, token, now)
        session_b.commit()
    finally:
        session_a.close()
        session_b.close()

    winners = [c for c in (claim_a, claim_b) if c is not None]
    assert len(winners) == 1, "exactly one concurrent claim may win"
    assert winners[0].user_id == admin_user.id

    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=token).one()
    assert row.is_valid is False, "the claimed refresh token must be invalidated"


def test_two_connection_refresh_race_exactly_one_wins(test_engine):
    """True concurrency: two INDEPENDENT DB connections race the full refresh flow
    (claim + mint successor) against the same token, released together by a
    barrier. On Postgres the conditional UPDATE row-locks the matching row, so
    exactly one connection claims it and mints a successor; the other blocks,
    re-evaluates the predicate after the winner commits, matches zero rows, and
    takes the route's 401 path.

    Rows are committed to the real test DB (outside the SAVEPOINT `db` fixture) so
    both connections see them; everything is uniquely marked and torn down in
    ``finally``. Each worker mirrors the /auth/refresh route: a None claim maps to
    the route's 401, a claimed row maps to a 200 that inserts exactly one successor.
    """
    IndepSession = sessionmaker(
        bind=test_engine, autoflush=False, expire_on_commit=False
    )
    marker = uuid.uuid4().hex
    username = f"pra252-race-{marker}"
    orig_token = f"pra252-orig-{marker}"
    now = datetime.utcnow()
    user_id = None

    try:
        # Seed a throwaway user + one valid refresh token, COMMITTED so independent
        # connections can see them.
        setup = IndepSession()
        try:
            user = User(
                username=username,
                email=f"{username}@example.com",
                hashed_password=get_password_hash("x"),
                is_active=True,
            )
            setup.add(user)
            setup.commit()
            user_id = user.id
            setup.add(
                RefreshToken(
                    token=orig_token,
                    user_id=user_id,
                    is_valid=True,
                    expires_at=now + timedelta(days=7),
                )
            )
            setup.commit()
        finally:
            setup.close()

        barrier = threading.Barrier(2)
        results: dict[str, str] = {}

        def worker(name: str) -> None:
            session = IndepSession()
            try:
                barrier.wait(timeout=10)  # release both threads together
                claimed = claim_refresh_token(session, orig_token, now)
                if claimed is None:
                    session.rollback()
                    results[name] = "401"  # route raises 401 here
                    return
                session.add(
                    RefreshToken(
                        token=f"pra252-succ-{marker}-{name}",
                        user_id=claimed.user_id,
                        is_valid=True,
                        expires_at=now + timedelta(days=7),
                    )
                )
                session.commit()
                results[name] = "200"
            except Exception as exc:  # pragma: no cover - surfaced by the assert
                results[name] = f"error:{exc!r}"
            finally:
                session.close()

        t1 = threading.Thread(target=worker, args=("a",))
        t2 = threading.Thread(target=worker, args=("b",))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        assert sorted(results.values()) == [
            "200",
            "401",
        ], f"expected exactly one 200 + one 401, got {results}"

        # Verify persisted state on a fresh independent connection.
        verify = IndepSession()
        try:
            orig = verify.query(RefreshToken).filter_by(token=orig_token).one()
            assert orig.is_valid is False, "original refresh token must be invalidated"
            valid = (
                verify.query(RefreshToken)
                .filter(
                    RefreshToken.user_id == user_id,
                    RefreshToken.is_valid.is_(True),
                )
                .all()
            )
            assert (
                len(valid) == 1
            ), f"exactly one valid successor must exist, got {len(valid)}"
        finally:
            verify.close()
    finally:
        # Tear down everything committed outside the SAVEPOINT fixture.
        cleanup = IndepSession()
        try:
            if user_id is not None:
                cleanup.query(RefreshToken).filter(
                    RefreshToken.user_id == user_id
                ).delete(synchronize_session=False)
                cleanup.query(User).filter(User.id == user_id).delete(
                    synchronize_session=False
                )
                cleanup.commit()
        finally:
            cleanup.close()


def test_claim_rejects_expired_and_already_claimed(db, admin_user):
    now = datetime.utcnow()

    # Expired row is never claimable.
    db.add(
        RefreshToken(
            token="pra252-expired",
            user_id=admin_user.id,
            is_valid=True,
            expires_at=now - timedelta(seconds=1),
        )
    )
    # Already-invalid row is never claimable.
    db.add(
        RefreshToken(
            token="pra252-invalid",
            user_id=admin_user.id,
            is_valid=False,
            expires_at=now + timedelta(days=7),
        )
    )
    db.commit()

    assert claim_refresh_token(db, "pra252-expired", now) is None
    assert claim_refresh_token(db, "pra252-invalid", now) is None
    assert claim_refresh_token(db, "pra252-unknown", now) is None


def _login(client):
    return client.post(
        "/auth/login", data={"username": "admintest", "password": "testpass123"}
    )


def test_refresh_route_persists_exactly_one_successor(client, admin_user, db):
    old_refresh = _login(client).json()["refresh_token"]

    res = client.post(f"/auth/refresh?token_refresh={old_refresh}")
    assert res.status_code == 200, res.text
    new_refresh = res.json()["refresh_token"]
    assert new_refresh != old_refresh

    db.expire_all()
    # Old row invalid, and exactly one valid successor for the user.
    assert db.query(RefreshToken).filter_by(token=old_refresh).one().is_valid is False
    valid = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == admin_user.id,
            RefreshToken.is_valid.is_(True),
        )
        .all()
    )
    assert len(valid) == 1, "exactly one valid refresh token must remain"
    assert valid[0].token == new_refresh


def test_replayed_refresh_token_is_rejected(client, admin_user):
    old = _login(client).json()["refresh_token"]
    first = client.post(f"/auth/refresh?token_refresh={old}")
    assert first.status_code == 200
    replay = client.post(f"/auth/refresh?token_refresh={old}")
    assert replay.status_code == 401
    assert replay.json()["detail"] == "Invalid or expired refresh token"
