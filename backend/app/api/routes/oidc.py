"""
OIDC authentication routes.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import OIDCProvider, User
from ...db.session import get_db
from ...services import outbound_http_guard
from ...services.oidc_service import OIDCError, OIDCService

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False, tags=["oidc"])


def _validate_discovery_url(discovery_url: str) -> None:
    """SSRF guard for an operator-supplied OIDC discovery URL.

    Rejects a discovery URL that is non-HTTPS or resolves to a
    loopback/private/link-local/metadata target, so a provider cannot be
    configured to make the backend fetch from an internal address. Delivery
    re-validates independently. ``OIDC_ALLOW_PRIVATE_TARGETS`` permits an
    on-network IdP.
    """
    try:
        outbound_http_guard.validate_target(
            discovery_url,
            require_https=True,
            allow_private=outbound_http_guard.oidc_allow_private_targets(),
        )
    except outbound_http_guard.SsrfBlocked as exc:
        raise HTTPException(
            status_code=400, detail=f"discovery_url not allowed: {exc}"
        ) from exc


def _public_base_url() -> str:
    """Externally reachable origin of the Praxis UI (browser-facing).

    The frontend proxies ``/api/backend/*`` to the backend, and the IdP
    redirects the *browser*, so OIDC redirect/completion URLs must be built
    from the public origin — not ``request.base_url`` (which is the internal
    ``backend:8000`` when the call arrives through the Next.js proxy).
    """
    return os.getenv("PUBLIC_BASE_URL", "http://localhost:3000").rstrip("/")


def _oidc_redirect_uri() -> str:
    """The single canonical redirect URI used at BOTH authorize and exchange.

    Operators can pin it explicitly via ``OIDC_REDIRECT_URI`` (the value they
    register with the IdP); otherwise it is derived from ``PUBLIC_BASE_URL``
    plus the frontend proxy path that maps to the backend callback.
    """
    explicit = os.getenv("OIDC_REDIRECT_URI")
    if explicit:
        return explicit.rstrip("/")
    return _public_base_url() + "/api/backend/auth/oidc/callback"


def _oidc_completion_redirect(
    *, error: Optional[str] = None, tokens: Optional[Dict] = None
) -> str:
    """Build the browser redirect back to the UI after the callback.

    On success the tokens are delivered in the URL *fragment* (``#...``), which
    browsers never send to servers and keep out of the Referer header / access
    logs; the login page reads them client-side and exchanges them for
    httpOnly cookies via ``/api/auth/oidc-complete``. On failure a short,
    non-sensitive ``oidc_error`` code is passed as a query parameter.
    """
    base = _public_base_url() + "/login"
    if error:
        return f"{base}?{urlencode({'oidc_error': error})}"
    fragment = urlencode(
        {"oidc_token": tokens["access_token"], "oidc_refresh": tokens["refresh_token"]}
    )
    return f"{base}#{fragment}"


# --- Schemas ---


class OIDCProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    discovery_url: str = Field(..., min_length=1)
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    role_claim: str = Field(default="roles")
    role_mapping: Optional[Dict[str, str]] = None
    enabled: bool = False


class OIDCProviderUpdate(BaseModel):
    name: Optional[str] = None
    discovery_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    role_claim: Optional[str] = None
    role_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None


class OIDCProviderResponse(BaseModel):
    id: int
    name: str
    discovery_url: str
    client_id: str
    role_claim: str
    role_mapping: Optional[Dict[str, str]] = None
    enabled: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


def provider_to_response(p: OIDCProvider) -> dict:
    role_mapping = None
    if p.role_mapping:
        try:
            role_mapping = json.loads(p.role_mapping)
        except json.JSONDecodeError:
            role_mapping = None

    return {
        "id": p.id,
        "name": p.name,
        "discovery_url": p.discovery_url,
        "client_id": p.client_id,
        "role_claim": p.role_claim,
        "role_mapping": role_mapping,
        "enabled": p.enabled,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


# --- Provider Config CRUD (admin only) ---


@router.get("/providers", response_model=List[OIDCProviderResponse])
async def list_providers(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),  # pylint: disable=unused-argument
):
    """List all OIDC providers."""
    service = OIDCService(db)
    providers = service.list_providers()
    return [provider_to_response(p) for p in providers]


@router.post(
    "/providers",
    response_model=OIDCProviderResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider(
    data: OIDCProviderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),  # pylint: disable=unused-argument
):
    """Create a new OIDC provider configuration."""
    _validate_discovery_url(data.discovery_url)
    provider = OIDCProvider(
        name=data.name,
        discovery_url=data.discovery_url,
        client_id=data.client_id,
        client_secret=data.client_secret,
        role_claim=data.role_claim,
        role_mapping=json.dumps(data.role_mapping) if data.role_mapping else None,
        enabled=data.enabled,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return provider_to_response(provider)


@router.put("/providers/{provider_id}", response_model=OIDCProviderResponse)
async def update_provider(
    provider_id: int,
    data: OIDCProviderUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),  # pylint: disable=unused-argument
):
    """Update an OIDC provider configuration."""
    provider = db.query(OIDCProvider).filter(OIDCProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    update_data = data.dict(exclude_unset=True)
    if update_data.get("discovery_url") is not None:
        _validate_discovery_url(update_data["discovery_url"])
    if "role_mapping" in update_data and update_data["role_mapping"] is not None:
        update_data["role_mapping"] = json.dumps(update_data["role_mapping"])

    for key, value in update_data.items():
        setattr(provider, key, value)

    db.commit()
    db.refresh(provider)
    return provider_to_response(provider)


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),  # pylint: disable=unused-argument
):
    """Delete an OIDC provider configuration."""
    provider = db.query(OIDCProvider).filter(OIDCProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.delete(provider)
    db.commit()


@router.post("/providers/test")
async def test_provider_connection(
    discovery_url: str = Query(..., description="OIDC discovery URL to test"),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin")
    ),  # pylint: disable=unused-argument
):
    """Test connectivity to an OIDC provider."""
    service = OIDCService(db)
    result = await service.test_connection(discovery_url)
    return result


# --- Auth Flow ---


@router.get("/status")
async def get_oidc_status(
    db: Session = Depends(get_db),
):
    """Get OIDC status (public — used by login page to show SSO button)."""
    provider = db.query(OIDCProvider).filter(OIDCProvider.enabled.is_(True)).first()
    if not provider:
        return {"enabled": False}
    return {"enabled": True, "provider_name": provider.name}


@router.get("/login")
async def oidc_login(
    db: Session = Depends(get_db),
):
    """Initiate OIDC login — redirects to provider."""
    service = OIDCService(db)
    provider = service.get_provider()
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No OIDC provider configured",
        )

    discovery_doc = await service.discover(provider.discovery_url)

    # Canonical, externally reachable redirect URI (PRA-217). Persisted with
    # the login state so the callback's token exchange re-uses the same value.
    redirect_uri = _oidc_redirect_uri()

    auth_url = service.generate_auth_url(provider, redirect_uri, discovery_doc)
    return {"auth_url": auth_url}


@router.get("/callback")
async def oidc_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """Handle OIDC callback — exchange code for tokens, provision user.

    The browser navigates here directly (the IdP redirect target), so the
    handler responds with a 302 back to the UI rather than JSON: tokens go in
    the URL fragment on success, a short ``oidc_error`` code on failure. The
    login page completes the flow by swapping the tokens for httpOnly cookies.
    """
    service = OIDCService(db)

    # Validate + consume state (single-use, TTL-bounded, shared across workers).
    state_data = service.consume_state(state)
    if not state_data:
        logger.warning("OIDC callback with invalid or expired state")
        return RedirectResponse(
            url=_oidc_completion_redirect(error="invalid_state"),
            status_code=status.HTTP_302_FOUND,
        )

    provider = service.get_provider_by_id(int(state_data["provider_id"]))
    if not provider:
        logger.warning("OIDC callback referenced missing provider")
        return RedirectResponse(
            url=_oidc_completion_redirect(error="sso_failed"),
            status_code=status.HTTP_302_FOUND,
        )

    try:
        discovery_doc = await service.discover(provider.discovery_url)

        # Re-use the EXACT redirect_uri sent at authorize time (PRA-217). The
        # token endpoint requires it to match the authorize request.
        redirect_uri = state_data["redirect_uri"]

        # Exchange code for tokens
        token_response = await service.exchange_code(
            provider, code, redirect_uri, discovery_doc
        )

        id_token = token_response.get("id_token")
        if not id_token:
            raise OIDCError("No id_token in token response")

        # Validate ID token
        claims = await service.validate_id_token(
            id_token,
            provider,
            discovery_doc,
            state_data["nonce"],
            token_response.get("access_token"),
        )

        # Map roles
        roles = service.map_roles(provider, claims)

        # Provision/update user
        issuer = discovery_doc.get("issuer", provider.discovery_url)
        user = service.provision_user(claims, roles, issuer)

        # Create Praxis tokens
        tokens = service.create_tokens(user)

        return RedirectResponse(
            url=_oidc_completion_redirect(tokens=tokens),
            status_code=status.HTTP_302_FOUND,
        )

    except OIDCError as e:
        # Log the detail server-side; surface only a generic code to the user.
        logger.error("OIDC callback error: %s", str(e))
        return RedirectResponse(
            url=_oidc_completion_redirect(error="sso_failed"),
            status_code=status.HTTP_302_FOUND,
        )
