"""PRA-304: the default bootstrap admin username avoids the managed Linux login
collision.

Per-user fleet access maps a Praxis username to the managed Linux login on each
host, and real hosts commonly already have an ``admin`` user/group (which PRA-286
ownership-marker hardening correctly fails closed on). So the default bootstrap
username is ``praxisadmin``, NOT ``admin`` — while the in-app ``admin``/Administrator
ROLE is unchanged. These tests pin that default and confirm no seeded flow creates a
managed ``admin`` login by default.
"""

from __future__ import annotations

import scripts.create_admin_user as cau
from app.db.models import Role, User


def _run(db, monkeypatch, **env):
    monkeypatch.setattr(cau, "SessionLocal", lambda: db)
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-pw-abc123")
    for key in ("ADMIN_USERNAME", "ADMIN_EMAIL"):
        monkeypatch.delenv(key, raising=False)
    for key, val in env.items():
        monkeypatch.setenv(key, val)
    cau.create_admin_user()


def test_default_bootstrap_username_is_praxisadmin(db, monkeypatch):
    _run(db, monkeypatch)

    # The bootstrap user is praxisadmin, and NO managed `admin` login is seeded.
    praxisadmin = db.query(User).filter_by(username="praxisadmin").first()
    assert praxisadmin is not None
    assert db.query(User).filter_by(username="admin").first() is None

    # The application Administrator role (Role.name == "admin") is intact and
    # assigned to the bootstrap user — only the Linux-login-bearing username changed.
    assert db.query(Role).filter_by(name="admin").first() is not None
    assert any(r.name == "admin" for r in praxisadmin.roles)


def test_bootstrap_username_env_override_is_honored(db, monkeypatch):
    _run(db, monkeypatch, ADMIN_USERNAME="ops-bootstrap")
    assert db.query(User).filter_by(username="ops-bootstrap").first() is not None
    # The default is not also created when an override is supplied.
    assert db.query(User).filter_by(username="praxisadmin").first() is None


def test_bootstrap_is_idempotent(db, monkeypatch):
    _run(db, monkeypatch)
    _run(db, monkeypatch)
    assert db.query(User).filter_by(username="praxisadmin").count() == 1


def test_no_password_creates_no_user(db, monkeypatch):
    """With ADMIN_PASSWORD unset the script must not seed any bootstrap login."""
    monkeypatch.setattr(cau, "SessionLocal", lambda: db)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    before = db.query(User).count()
    cau.create_admin_user()
    assert db.query(User).count() == before
    assert db.query(User).filter_by(username="praxisadmin").first() is None
