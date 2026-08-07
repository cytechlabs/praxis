"""PRA-243: OIDC account linking + role mapping fail closed.

Regression guard against OIDC account takeover:

- identity binds ONLY to the stable ``(oidc_issuer, oidc_sub)`` pair;
- a new OIDC subject whose username/email collides with an existing account fails
  closed and never mutates that account;
- creating a new OIDC user requires a verified email claim;
- inactive linked users cannot receive tokens;
- external role claims grant Praxis roles only through the provider's explicit
  ``role_mapping`` allowlist — a hostile ``roles: ["admin"]`` claim grants nothing.
"""

import pytest

from app.core.auth import get_password_hash
from app.db.models import OIDCProvider, User
from app.services.oidc_service import DEFAULT_OIDC_ROLE, OIDCError, OIDCService

ISSUER = "https://idp.example.com"


def _provider(db, *, role_mapping=None, role_claim="roles") -> OIDCProvider:
    p = OIDCProvider(
        name="Test IdP",
        discovery_url=ISSUER,
        client_id="praxis-client",
        client_secret="shh",
        role_claim=role_claim,
        role_mapping=role_mapping,
        enabled=True,
    )
    db.add(p)
    db.flush()
    return p


def _claims(
    *,
    sub="sub-1",
    email="new@example.com",
    email_verified=True,
    username=None,
    roles=None,
):
    c = {"sub": sub, "email": email, "email_verified": email_verified}
    if username is not None:
        c["preferred_username"] = username
    if roles is not None:
        c["roles"] = roles
    return c


def _local_user(
    db, *, username, email, is_active=True, oidc_sub=None, oidc_issuer=None
):
    u = User(
        username=username,
        email=email,
        hashed_password=get_password_hash("localpass"),
        is_active=is_active,
        oidc_sub=oidc_sub,
        oidc_issuer=oidc_issuer,
    )
    db.add(u)
    db.flush()
    return u


# --------------------------------------------------- stable-identity linking


def test_existing_linked_user_logs_in(db, seed_roles):
    svc = OIDCService(db)
    u = _local_user(
        db,
        username="stable",
        email="stable@x.com",
        oidc_sub="stable-sub",
        oidc_issuer=ISSUER,
    )
    out = svc.provision_user(
        _claims(sub="stable-sub", email="stable@x.com"), ["maintainer"], ISSUER
    )
    assert out.id == u.id
    assert sorted(r.name for r in out.roles) == ["maintainer"]


def test_new_verified_user_created_active(db, seed_roles):
    svc = OIDCService(db)
    user = svc.provision_user(
        _claims(sub="new-sub", email="new@example.com", username="newuser"),
        ["auditor"],
        ISSUER,
    )
    assert user.id is not None
    assert user.is_active is True
    assert user.oidc_sub == "new-sub"
    assert user.oidc_issuer == ISSUER
    assert [r.name for r in user.roles] == ["auditor"]


def test_missing_sub_rejected(db):
    svc = OIDCService(db)
    with pytest.raises(OIDCError):
        svc.provision_user(
            {"email": "x@y.com", "email_verified": True}, ["auditor"], ISSUER
        )


# --------------------------------------------------- takeover: no auto-linking


def test_local_admin_username_collision_fails_closed(db, seed_roles):
    svc = OIDCService(db)
    admin = _local_user(db, username="admin", email="admin@corp.local")
    # A hostile IdP asserts preferred_username=admin with its own verified email.
    claims = _claims(
        sub="attacker-sub", email="attacker@evil.example", username="admin"
    )
    with pytest.raises(OIDCError):
        svc.provision_user(claims, ["auditor"], ISSUER)
    db.refresh(admin)
    assert admin.oidc_sub is None
    assert admin.oidc_issuer is None
    # No account ever got bound to the attacker subject.
    assert db.query(User).filter(User.oidc_sub == "attacker-sub").first() is None


def test_local_email_collision_fails_closed(db, seed_roles):
    svc = OIDCService(db)
    victim = _local_user(db, username="alice", email="alice@corp.local")
    claims = _claims(
        sub="attacker-sub-2", email="alice@corp.local", username="someoneelse"
    )
    with pytest.raises(OIDCError):
        svc.provision_user(claims, ["auditor"], ISSUER)
    db.refresh(victim)
    assert victim.oidc_sub is None
    assert db.query(User).filter(User.oidc_sub == "attacker-sub-2").first() is None


# --------------------------------------------------- verified-email requirement


def test_unverified_email_creates_no_user(db, seed_roles):
    svc = OIDCService(db)
    claims = _claims(
        sub="unv-sub", email="unv@example.com", email_verified=False, username="unv"
    )
    with pytest.raises(OIDCError):
        svc.provision_user(claims, ["auditor"], ISSUER)
    assert db.query(User).filter(User.oidc_sub == "unv-sub").first() is None


def test_missing_email_verified_flag_creates_no_user(db, seed_roles):
    svc = OIDCService(db)
    claims = {"sub": "nv-sub", "email": "nv@example.com", "preferred_username": "nv"}
    with pytest.raises(OIDCError):
        svc.provision_user(claims, ["auditor"], ISSUER)
    assert db.query(User).filter(User.oidc_sub == "nv-sub").first() is None


def test_missing_email_creates_no_user(db, seed_roles):
    svc = OIDCService(db)
    claims = {"sub": "ne-sub", "email_verified": True, "preferred_username": "ne"}
    with pytest.raises(OIDCError):
        svc.provision_user(claims, ["auditor"], ISSUER)
    assert db.query(User).filter(User.oidc_sub == "ne-sub").first() is None


# --------------------------------------------------- inactive users


def test_inactive_linked_user_rejected_in_provision(db, seed_roles):
    svc = OIDCService(db)
    _local_user(
        db,
        username="ghost",
        email="ghost@x.com",
        is_active=False,
        oidc_sub="ghost-sub",
        oidc_issuer=ISSUER,
    )
    with pytest.raises(OIDCError):
        svc.provision_user(
            _claims(sub="ghost-sub", email="ghost@x.com"), ["auditor"], ISSUER
        )


def test_create_tokens_rejects_inactive_user(db):
    svc = OIDCService(db)
    u = _local_user(db, username="inactive", email="inactive@x.com", is_active=False)
    with pytest.raises(OIDCError):
        svc.create_tokens(u)


# --------------------------------------------------- role mapping allowlist


def test_hostile_admin_claim_no_passthrough(db):
    svc = OIDCService(db)
    provider = _provider(db, role_mapping=None)
    assert svc.map_roles(provider, {"roles": ["admin"]}) == [DEFAULT_OIDC_ROLE]


def test_praxis_role_name_not_allowlisted_is_ignored(db):
    # role_mapping exists but does not allowlist the literal "admin" value.
    svc = OIDCService(db)
    provider = _provider(db, role_mapping='{"praxis-admin": "admin"}')
    assert svc.map_roles(provider, {"roles": ["admin"]}) == [DEFAULT_OIDC_ROLE]


def test_positive_explicit_role_mapping(db):
    svc = OIDCService(db)
    provider = _provider(
        db, role_mapping='{"praxis-admin": "admin", "praxis-ops": "maintainer"}'
    )
    assert svc.map_roles(provider, {"roles": ["praxis-admin"]}) == ["admin"]
    assert svc.map_roles(provider, {"roles": ["praxis-ops"]}) == ["maintainer"]


def test_mapping_to_invalid_internal_role_is_dropped(db):
    svc = OIDCService(db)
    provider = _provider(db, role_mapping='{"grp": "superadmin"}')
    assert svc.map_roles(provider, {"roles": ["grp"]}) == [DEFAULT_OIDC_ROLE]


def test_invalid_role_mapping_json_defaults_auditor(db):
    svc = OIDCService(db)
    provider = _provider(db, role_mapping="{not valid json")
    assert svc.map_roles(provider, {"roles": ["praxis-admin"]}) == [DEFAULT_OIDC_ROLE]


def test_hostile_admin_end_to_end_provisions_auditor(db, seed_roles):
    # map_roles + provision_user together: a hostile admin claim yields an auditor.
    svc = OIDCService(db)
    provider = _provider(db, role_mapping=None)
    claims = _claims(
        sub="h-sub", email="h@example.com", username="hostile", roles=["admin"]
    )
    roles = svc.map_roles(provider, claims)
    user = svc.provision_user(claims, roles, ISSUER)
    assert [r.name for r in user.roles] == ["auditor"]
    assert not any(r.name == "admin" for r in user.roles)
