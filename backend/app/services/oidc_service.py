"""
OIDC service for generic OpenID Connect provider integration.
"""

import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from jose import JWTError, jwt
from sqlalchemy import delete as sa_delete
from sqlalchemy.orm import Session

from ..core.auth import create_access_token, create_refresh_token, get_password_hash
from ..db.models import OIDCLoginState, OIDCProvider, RefreshToken, Role, User
from . import outbound_http_guard

logger = logging.getLogger(__name__)

# OIDC login state/nonce are persisted in the ``oidc_login_state`` table
# (see OIDCService.generate_auth_url / consume_state) so the flow works across
# the multiple uvicorn workers production runs (PRA-218). The previous
# in-memory dict only worked for a single-process deployment.
OIDC_STATE_TTL_SECONDS = 600  # 10 min authorize->callback window

# Internal Praxis role names an external IdP claim is ever allowed to resolve to.
# An external role value only grants one of these when the provider's
# ``role_mapping`` allowlist maps it there (PRA-243): the IdP can never hand us a
# Praxis role name directly.
VALID_PRAXIS_ROLES = frozenset({"admin", "maintainer", "auditor", "viewer"})
DEFAULT_OIDC_ROLE = "auditor"


class OIDCError(Exception):
    """Exception raised for OIDC operations."""


class OIDCService:
    """Service for OIDC provider operations."""

    def __init__(self, db: Session):
        self.db = db
        self._discovery_cache: Dict[str, Dict] = {}

    def get_provider(self) -> Optional[OIDCProvider]:
        """Get the enabled OIDC provider (single provider supported)."""
        return (
            self.db.query(OIDCProvider).filter(OIDCProvider.enabled.is_(True)).first()
        )

    def get_provider_by_id(self, provider_id: int) -> Optional[OIDCProvider]:
        """Get a specific OIDC provider."""
        return (
            self.db.query(OIDCProvider).filter(OIDCProvider.id == provider_id).first()
        )

    def list_providers(self):
        """List all OIDC providers."""
        return self.db.query(OIDCProvider).all()

    @staticmethod
    def _allow_private() -> bool:
        """Whether an on-network IdP is explicitly allowed (OIDC escape hatch)."""
        return outbound_http_guard.oidc_allow_private_targets()

    @staticmethod
    def _require(url: Optional[str], label: str) -> str:
        """Return *url* or raise ``OIDCError`` if the discovery doc omitted it.

        Discovery documents are attacker-influenceable, so the backend-fetched
        endpoints (``token_endpoint``, ``jwks_uri``) get their full SSRF check
        (HTTPS, DNS-resolved, internal targets rejected, pinned) at the moment of
        the fetch via ``outbound_http_guard.get_async`` / ``post_async``; this only
        guarantees the key is present. Endpoints are NOT required to share the
        issuer's origin (standards-compliant providers legitimately split them,
        e.g. issuer ``accounts.google.com`` with JWKS on ``www.googleapis.com``),
        so the guard, not same-origin, is the SSRF boundary.
        """
        if not url:
            raise OIDCError(f"discovery document missing {label}")
        return url

    def _validate_browser_endpoint(self, url: Optional[str], label: str) -> str:
        """Validate a discovery-controlled URL the browser (not the backend) will
        navigate to: the ``authorization_endpoint``.

        The backend never fetches this URL, so a full DNS-resolve+pin is the wrong
        tool (and would make login depend on the backend resolving a browser-only
        host). Instead it is shape-validated: HTTPS required, host present,
        loopback/private/metadata *literals* and local names rejected. Raises
        ``OIDCError`` on a disallowed endpoint.
        """
        self._require(url, label)
        try:
            outbound_http_guard.validate_url_shape(
                url, require_https=True, allow_private=self._allow_private()
            )
        except outbound_http_guard.SsrfBlocked as exc:
            raise OIDCError(f"{label} not allowed: {exc}") from exc
        return url

    async def discover(self, discovery_url: str) -> Dict[str, Any]:
        """Fetch OIDC discovery document through the SSRF guard.

        The discovery URL is validated (HTTPS, DNS-resolved, internal targets
        rejected) at runtime BEFORE the cache is consulted, so a cached document
        never lets a later request skip validation (a target that has since
        rebound or been reconfigured to an internal address is caught). On a cache
        miss the fetch itself re-validates + pins with redirects disabled.
        """
        url = discovery_url
        if not url.endswith("/.well-known/openid-configuration"):
            url = url.rstrip("/") + "/.well-known/openid-configuration"

        # Runtime validation runs on every call, cache hit or miss, so the cache
        # cannot bypass the SSRF guard.
        try:
            outbound_http_guard.validate_target(
                url, require_https=True, allow_private=self._allow_private()
            )
        except outbound_http_guard.SsrfBlocked as exc:
            raise OIDCError(f"discovery target not allowed: {exc}") from exc

        if discovery_url in self._discovery_cache:
            return self._discovery_cache[discovery_url]

        try:
            response = await outbound_http_guard.get_async(
                url, timeout=10, require_https=True, allow_private=self._allow_private()
            )
        except outbound_http_guard.SsrfBlocked as exc:
            raise OIDCError(f"discovery target not allowed: {exc}") from exc

        if response.status_code != 200:
            raise OIDCError(
                f"Failed to fetch discovery document: {response.status_code}"
            )

        doc = response.json()
        self._discovery_cache[discovery_url] = doc
        return doc

    def generate_auth_url(
        self, provider: OIDCProvider, redirect_uri: str, discovery_doc: Dict
    ) -> str:
        """Generate the OIDC authorization URL and persist the login state.

        ``state`` / ``nonce`` and the exact ``redirect_uri`` are written to the
        shared ``oidc_login_state`` table so the callback (which may run on a
        different worker) can validate them and re-use the identical
        redirect_uri for the token exchange.
        """
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Opportunistic sweep of expired rows so the table does not grow.
        self.cleanup_expired_states()

        self.db.add(
            OIDCLoginState(
                state=state,
                nonce=nonce,
                provider_id=provider.id,
                redirect_uri=redirect_uri,
                expires_at=datetime.utcnow()
                + timedelta(seconds=OIDC_STATE_TTL_SECONDS),
            )
        )
        self.db.commit()

        # Validate the discovered authorization endpoint before handing it to the
        # browser (rejects an internal/non-HTTPS endpoint from a hostile doc).
        auth_endpoint = self._validate_browser_endpoint(
            discovery_doc.get("authorization_endpoint"), "authorization_endpoint"
        )
        # urlencode so values containing ``:`` / ``/`` (the redirect_uri) and
        # any reserved characters are escaped correctly for every IdP.
        query = urlencode(
            {
                "response_type": "code",
                "client_id": provider.client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid email profile",
                "state": state,
                "nonce": nonce,
            }
        )
        return f"{auth_endpoint}?{query}"

    async def exchange_code(
        self,
        provider: OIDCProvider,
        code: str,
        redirect_uri: str,
        discovery_doc: Dict,
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        # The token endpoint is fetched by the backend with the client secret +
        # auth code, so the SSRF check (HTTPS, DNS-resolved, internal rejected,
        # pinned) runs at the fetch below via ``post_async``; here just require it.
        token_endpoint = self._require(
            discovery_doc.get("token_endpoint"), "token_endpoint"
        )

        body = urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            }
        ).encode("utf-8")

        try:
            response = await outbound_http_guard.post_async(
                token_endpoint,
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
                require_https=True,
                allow_private=self._allow_private(),
            )
        except outbound_http_guard.SsrfBlocked as exc:
            raise OIDCError(f"token_endpoint not allowed: {exc}") from exc

        if response.status_code != 200:
            # Never surface the raw IdP error body (may echo the code/secret).
            raise OIDCError(f"Token exchange failed: {response.status_code}")

        return response.json()

    async def validate_id_token(
        self,
        id_token: str,
        provider: OIDCProvider,
        discovery_doc: Dict,
        nonce: str,
        access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate the ID token and return claims."""
        # The JWKS endpoint is fetched by the backend, so its SSRF check runs at
        # the fetch below via ``get_async``; here just require it to be present.
        jwks_uri = self._require(discovery_doc.get("jwks_uri"), "jwks_uri")

        try:
            jwks_response = await outbound_http_guard.get_async(
                jwks_uri,
                timeout=10,
                require_https=True,
                allow_private=self._allow_private(),
            )
        except outbound_http_guard.SsrfBlocked as exc:
            raise OIDCError(f"jwks_uri not allowed: {exc}") from exc
        jwks = jwks_response.json()

        # Get the token header to find the key ID
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")

        # Find the matching key
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if not rsa_key:
            raise OIDCError("Unable to find matching key in JWKS")

        try:
            claims = jwt.decode(
                id_token,
                rsa_key,
                algorithms=["RS256"],
                audience=provider.client_id,
                issuer=discovery_doc.get("issuer"),
                access_token=access_token,
            )
        except JWTError as e:
            raise OIDCError(f"ID token validation failed: {str(e)}") from e

        # Verify nonce
        if claims.get("nonce") != nonce:
            raise OIDCError("Nonce mismatch")

        return claims

    def map_roles(self, provider: OIDCProvider, claims: Dict) -> list:
        """Resolve Praxis roles from OIDC claims through the provider's explicit
        allowlist ONLY (PRA-243).

        An external role value grants an internal Praxis role solely when
        ``provider.role_mapping`` maps it to a valid internal role name. There is
        no direct pass-through: a hostile/misconfigured claim like
        ``roles: ["admin"]`` does not grant admin unless a configured external
        value is explicitly mapped to ``admin``. When no allowlisted value applies
        (missing claim, empty/invalid mapping, no match), the login falls back to
        the least-privilege default (``auditor``).
        """
        role_claim = provider.role_claim or "roles"

        # Get the claim value (could be nested with dots, e.g., "resource_access.praxis.roles")
        claim_value = claims
        for part in role_claim.split("."):
            if isinstance(claim_value, dict):
                claim_value = claim_value.get(part)
            else:
                claim_value = None
                break

        if claim_value is None:
            logger.warning("Role claim '%s' not found in token claims", role_claim)
            return [DEFAULT_OIDC_ROLE]

        # Normalize to list
        if isinstance(claim_value, str):
            claim_value = [claim_value]
        if not isinstance(claim_value, list):
            logger.warning("Role claim '%s' is not a string/list", role_claim)
            return [DEFAULT_OIDC_ROLE]

        # Parse the explicit external->internal allowlist. An absent/invalid
        # mapping means "no external role is allowlisted" -> everyone defaults to
        # auditor (fail closed, no direct pass-through).
        role_mapping: Dict[str, Any] = {}
        if provider.role_mapping:
            try:
                parsed = json.loads(provider.role_mapping)
                if isinstance(parsed, dict):
                    role_mapping = parsed
                else:
                    logger.error(
                        "role_mapping for provider %s is not a JSON object",
                        provider.name,
                    )
            except json.JSONDecodeError:
                logger.error("Invalid role_mapping JSON for provider %s", provider.name)

        mapped_roles = []
        for val in claim_value:
            internal = role_mapping.get(str(val))
            # Only emit an internal role that was explicitly allowlisted AND is a
            # real Praxis role. The IdP value itself is never used as a role name.
            if internal in VALID_PRAXIS_ROLES and internal not in mapped_roles:
                mapped_roles.append(internal)

        return mapped_roles or [DEFAULT_OIDC_ROLE]

    def provision_user(self, claims: Dict, roles: list, issuer: str) -> User:
        """Resolve or create the OIDC-managed user, failing closed (PRA-243).

        Identity is bound ONLY to the stable ``(oidc_issuer, oidc_sub)`` pair:

        * An existing user with this exact pair logs in (rejected if inactive).
        * Otherwise this is a brand-new OIDC subject. It may create a user only
          when the IdP asserts a verified email AND neither the derived username
          nor the email already belongs to some other account.
        * A username/email collision with an existing (local or other-issuer)
          account **fails closed** — the existing account is never mutated into an
          OIDC-linked one. This removes the account-takeover vector where a
          hostile/misconfigured IdP claim matching a local admin's
          username/email could bind that subject to the admin account.
        """
        sub = claims.get("sub")
        if not sub:
            raise OIDCError("OIDC token has no subject (sub) claim")

        # Stable-identity lookup only — never by username/email.
        user = (
            self.db.query(User)
            .filter(User.oidc_sub == sub, User.oidc_issuer == issuer)
            .first()
        )

        if user is not None:
            if not user.is_active:
                raise OIDCError("linked OIDC user is inactive")
            self._apply_oidc_roles(user, roles)
            self.db.commit()
            self.db.refresh(user)
            return user

        # --- brand-new OIDC subject -----------------------------------------
        # Require a verified email claim before creating an account.
        email = claims.get("email")
        if not email or claims.get("email_verified") is not True:
            raise OIDCError("OIDC email is missing or not verified")

        username = claims.get("preferred_username") or email or sub

        # Fail closed on any username/email collision with an existing account.
        # Do NOT link or mutate that account.
        collision = (
            self.db.query(User)
            .filter((User.username == username) | (User.email == email))
            .first()
        )
        if collision is not None:
            logger.warning(
                "OIDC provisioning denied: username/email collides with existing "
                "account id=%s (no auto-linking)",
                collision.id,
            )
            raise OIDCError("OIDC identity collides with an existing account")

        user = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(secrets.token_urlsafe(32)),
            is_active=True,
            oidc_sub=sub,
            oidc_issuer=issuer,
        )
        self.db.add(user)
        self._apply_oidc_roles(user, roles)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _apply_oidc_roles(self, user: User, roles: list) -> None:
        """Sync the user's roles from the (already allowlist-mapped) role names,
        keeping only names that exist as real Praxis roles.

        PRA-290: role sync goes through the SAME identity-access path as the admin
        role-update endpoint (``identity_access_service.apply_role_assignment``), so
        federated role changes atomically recompute grants instead of being a
        separate ``user.roles = ...`` policy path. Kept fail-closed: an IdP that
        maps to no known Praxis role does not clear the user's existing roles.
        """
        db_roles = []
        for role_name in roles:
            role = self.db.query(Role).filter(Role.name == role_name).first()
            if role:
                db_roles.append(role)
        if db_roles:
            from . import identity_access_service

            identity_access_service.apply_role_assignment(self.db, user, db_roles)

    def create_tokens(self, user: User) -> Dict[str, str]:
        """Create access and refresh tokens for the OIDC-authenticated user.

        Defense-in-depth (PRA-243): refuse to mint tokens for an inactive account
        regardless of how we got here, so no caller can bypass the active check in
        ``provision_user``.
        """
        if not user.is_active:
            raise OIDCError("cannot issue tokens for an inactive user")

        access_token = create_access_token(data={"sub": user.username})
        refresh_token_str = create_refresh_token(data={"sub": user.username})

        # Store refresh token in DB
        refresh_record = RefreshToken(
            token=refresh_token_str,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True,
        )
        self.db.add(refresh_record)
        self.db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
        }

    @staticmethod
    def _consume_state_stmt(state: str):
        """Build the atomic claim statement: a single ``DELETE ... RETURNING``.

        Doing the lookup and the delete as one statement makes consumption
        strictly one-time-use under the production multi-worker topology: if
        two callbacks race for the same ``state``, Postgres serializes the row
        delete, so only one transaction deletes the row and gets the RETURNING
        payload; the other matches zero rows. A prior read-then-delete left a
        window where both callbacks could read the row before either delete
        committed (PRA-218 review fix).
        """
        return (
            sa_delete(OIDCLoginState)
            .where(OIDCLoginState.state == state)
            .returning(
                OIDCLoginState.nonce,
                OIDCLoginState.provider_id,
                OIDCLoginState.redirect_uri,
                OIDCLoginState.expires_at,
            )
            .execution_options(synchronize_session=False)
        )

    def consume_state(self, state: str) -> Optional[Dict[str, str]]:
        """Validate and consume an OIDC ``state`` (single-use, TTL-bounded).

        Returns ``{"nonce", "provider_id", "redirect_uri"}`` on success, or
        ``None`` when the state is unknown, already used, or expired. The row
        is claimed with an atomic ``DELETE ... RETURNING`` (see
        ``_consume_state_stmt``) and the delete is committed so the
        consumption is visible to every worker; an expired row is still
        consumed (deleted) but reported as invalid.
        """
        row = self.db.execute(self._consume_state_stmt(state)).first()
        self.db.commit()
        if row is None:
            return None

        if row.expires_at < datetime.utcnow():
            return None
        return {
            "nonce": row.nonce,
            "provider_id": str(row.provider_id),
            "redirect_uri": row.redirect_uri,
        }

    def cleanup_expired_states(self) -> int:
        """Delete expired OIDC login-state rows. Returns the row count."""
        count = (
            self.db.query(OIDCLoginState)
            .filter(OIDCLoginState.expires_at < datetime.utcnow())
            .delete(synchronize_session=False)
        )
        self.db.commit()
        return count

    async def test_connection(self, discovery_url: str) -> Dict[str, Any]:
        """Test connectivity to an OIDC provider."""
        try:
            doc = await self.discover(discovery_url)
            return {
                "success": True,
                "issuer": doc.get("issuer"),
                "authorization_endpoint": doc.get("authorization_endpoint"),
                "token_endpoint": doc.get("token_endpoint"),
                "userinfo_endpoint": doc.get("userinfo_endpoint"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
