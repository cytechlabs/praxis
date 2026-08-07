"""PRA-180 Remediation 1A: OIDC shared login-state + redirect consistency.

Covers PRA-217 (one canonical redirect_uri used at authorize and exchange) and
PRA-218 (state/nonce persisted with TTL + single-use semantics so the flow is
correct across multiple production workers).
"""

from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy.dialects import postgresql

from app.db.models import OIDCLoginState, OIDCProvider
from app.services import oidc_service
from app.services.oidc_service import OIDCService

DISCOVERY = {"authorization_endpoint": "https://idp.example.com/authorize"}
REDIRECT_URI = "https://praxis.example.com/api/backend/auth/oidc/callback"


@pytest.fixture
def provider(db):
    p = OIDCProvider(
        name="Test IdP",
        discovery_url="https://idp.example.com",
        client_id="praxis-client",
        client_secret="shh",
        role_claim="roles",
        enabled=True,
    )
    db.add(p)
    db.flush()
    return p


def _state_from_url(auth_url: str) -> str:
    qs = parse_qs(urlparse(auth_url).query)
    return qs["state"][0]


def test_generate_auth_url_persists_state(db, provider):
    svc = OIDCService(db)
    url = svc.generate_auth_url(provider, REDIRECT_URI, DISCOVERY)

    assert url.startswith("https://idp.example.com/authorize?")
    qs = parse_qs(urlparse(url).query)
    # redirect_uri is round-tripped through urlencode intact
    assert qs["redirect_uri"][0] == REDIRECT_URI
    assert qs["response_type"][0] == "code"

    state = qs["state"][0]
    row = db.query(OIDCLoginState).filter_by(state=state).one()
    assert row.redirect_uri == REDIRECT_URI
    assert row.provider_id == provider.id
    assert row.expires_at > datetime.utcnow()


def test_consume_state_returns_data_and_redirect(db, provider):
    svc = OIDCService(db)
    url = svc.generate_auth_url(provider, REDIRECT_URI, DISCOVERY)
    state = _state_from_url(url)

    data = svc.consume_state(state)
    assert data is not None
    assert data["provider_id"] == str(provider.id)
    assert data["redirect_uri"] == REDIRECT_URI  # PRA-217: same URI at exchange
    assert data["nonce"]


def test_consume_state_is_single_use(db, provider):
    svc = OIDCService(db)
    state = _state_from_url(svc.generate_auth_url(provider, REDIRECT_URI, DISCOVERY))

    assert svc.consume_state(state) is not None
    # Replay finds nothing — the row was deleted.
    assert svc.consume_state(state) is None
    assert db.query(OIDCLoginState).filter_by(state=state).first() is None


def test_consume_state_compiles_to_atomic_delete_returning():
    """PRA-218 review fix: consumption is a single ``DELETE ... RETURNING``.

    A true concurrent-callback race needs two independent DB connections, which
    the single-connection savepoint test fixture cannot model. Instead we prove
    the claim is one atomic statement (not read-then-delete): under Postgres a
    single ``DELETE ... RETURNING`` serializes the row delete, so only one of
    two racing callbacks deletes the row and receives the RETURNING payload.
    """
    stmt = OIDCService._consume_state_stmt("some-state")
    sql = str(stmt.compile(dialect=postgresql.dialect())).lower()
    assert "delete from oidc_login_state" in sql
    assert "returning" in sql


def test_consume_state_unknown_returns_none(db):
    svc = OIDCService(db)
    assert svc.consume_state("never-issued") is None


def test_consume_state_rejects_and_clears_expired(db, provider):
    svc = OIDCService(db)
    db.add(
        OIDCLoginState(
            state="expired-state",
            nonce="n",
            provider_id=provider.id,
            redirect_uri=REDIRECT_URI,
            expires_at=datetime.utcnow() - timedelta(seconds=1),
        )
    )
    db.flush()

    assert svc.consume_state("expired-state") is None
    # Expired row is still consumed (deleted) so it cannot linger.
    assert db.query(OIDCLoginState).filter_by(state="expired-state").first() is None


def test_cleanup_expired_states_only_removes_expired(db, provider):
    svc = OIDCService(db)
    db.add(
        OIDCLoginState(
            state="old",
            nonce="n",
            provider_id=provider.id,
            redirect_uri=REDIRECT_URI,
            expires_at=datetime.utcnow() - timedelta(minutes=5),
        )
    )
    db.add(
        OIDCLoginState(
            state="fresh",
            nonce="n",
            provider_id=provider.id,
            redirect_uri=REDIRECT_URI,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )
    )
    db.flush()

    removed = svc.cleanup_expired_states()
    assert removed >= 1
    assert db.query(OIDCLoginState).filter_by(state="old").first() is None
    assert db.query(OIDCLoginState).filter_by(state="fresh").first() is not None


@pytest.mark.asyncio
async def test_validate_id_token_passes_access_token_for_at_hash(
    db, provider, monkeypatch
):
    """Keycloak emits at_hash; python-jose needs access_token to verify it."""

    class FakeJWKSResponse:
        def json(self):
            return {"keys": [{"kid": "kid-1"}]}

    captured = {}

    async def fake_get_async(_url, **_kwargs):
        # JWKS is now fetched through the SSRF guard; stub it out.
        return FakeJWKSResponse()

    def fake_decode(*_args, **kwargs):
        captured["access_token"] = kwargs.get("access_token")
        return {"nonce": "expected-nonce", "sub": "user-1"}

    monkeypatch.setattr(oidc_service.outbound_http_guard, "get_async", fake_get_async)
    monkeypatch.setattr(
        oidc_service.jwt, "get_unverified_header", lambda _token: {"kid": "kid-1"}
    )
    monkeypatch.setattr(oidc_service.jwt, "decode", fake_decode)

    claims = await OIDCService(db).validate_id_token(
        "id-token",
        provider,
        {
            "jwks_uri": "https://idp.example.com/certs",
            "issuer": "https://idp.example.com",
        },
        "expected-nonce",
        "keycloak-access-token",
    )

    assert claims["sub"] == "user-1"
    assert captured["access_token"] == "keycloak-access-token"
