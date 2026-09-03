"""Praxis API module: Main entry point for the FastAPI application."""

import logging
import os
import time
import uuid
from datetime import datetime

from dotenv import load_dotenv  # pylint: disable=wrong-import-order
from fastapi import (  # pylint: disable=wrong-import-order
    Depends,
    FastAPI,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware  # pylint: disable=wrong-import-order
from fastapi.responses import JSONResponse  # pylint: disable=wrong-import-order
from slowapi import _rate_limit_exceeded_handler  # pylint: disable=wrong-import-order
from slowapi.errors import RateLimitExceeded  # pylint: disable=wrong-import-order
from starlette.middleware.base import (  # pylint: disable=wrong-import-order
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.middleware.errors import (  # pylint: disable=wrong-import-order
    ServerErrorMiddleware,
)
from starlette.middleware.trustedhost import (  # pylint: disable=wrong-import-order
    TrustedHostMiddleware,
)
from starlette.responses import Response  # pylint: disable=wrong-import-order

from app.api.routes import (
    access_requests_router,
    access_reviews_router,
    activation_tokens_router,
    activity_feed_router,
    agent_bootstrap_router,
    agent_enroll_router,
    agent_router,
    airgap_router,
    alerts_router,
    analytics_router,
    app_settings_router,
    audit_router,
    audits_router,
    auth_router,
    baselines_router,
    bulk_router,
    command_approvals_router,
    command_execution_router,
    command_result_processing_router,
    command_whitelist_router,
    compliance_checks_router,
    compliance_exports_router,
    compliance_fleet_router,
    compliance_policies_router,
    compliance_remediation_executions_router,
    compliance_remediation_fleet_router,
    compliance_remediation_plans_router,
    compliance_remediation_router,
    compliance_starter_pack_router,
    compliance_systems_router,
    connection_settings_router,
    content_channels_router,
    content_profile_apply_router,
    content_profile_systems_router,
    content_profiles_router,
    credentials_router,
    diagnostics_router,
    edition_router,
    export_router,
    facts_router,
    file_transfer_router,
    fleet_access_router,
    fleet_operations_router,
    groups_router,
    health_router,
    jobs_router,
    lifecycle_fleet_router,
    lifecycle_router,
    maintenance_windows_router,
    mirror_serve_credentials_router,
    mirror_serve_router,
    mirror_upstream_keys_router,
    mirrors_router,
    notification_preferences_router,
    notifications_router,
    onboarding_router,
    package_reports_router,
    packages_router,
    patch_advisories_router,
    patch_executions_router,
    patch_policies_router,
    patch_rings_router,
    patch_update_plans_router,
    recordings_router,
    reports_router,
    repos_router,
    session_approvals_router,
    session_locks_router,
    sessions_router,
    smart_groups_router,
    ssh_identity_router,
    ssh_router,
    ssh_security_router,
    system_compare_router,
    system_patch_advisories_router,
    system_patch_policy_router,
    system_patch_ring_router,
    system_status_router,
    systems_router,
    tags_router,
    totp_router,
    users_router,
    vault_router,
    views_router,
)
from app.api.routes.oidc import router as oidc_router
from app.core.entitlements import (
    ACCESS_ACCESS_REVIEWS,
    ACCESS_SESSION_APPROVALS,
    ACCESS_SESSION_LOCKS,
    COMMANDS_APPROVALS,
    COMPLIANCE_BULK_EXPORTS,
    require_entitlement,
)
from app.ee.loader import load_ee

# Load environment variables first, before any other imports

load_dotenv(override=True)

# Verify required environment variables
required_env_vars = ["SECRET_KEY", "ALGORITHM", "ACCESS_TOKEN_EXPIRE_MINUTES"]
for var in required_env_vars:
    if not os.getenv(var):
        raise ValueError(f"Required environment variable {var} is not set")

# PRA-179 Slice 5: production-only fail-clear validation. The closed-set
# ENVIRONMENT check inside validate_production_env fires in every mode
# (so ``ENVIRONMENT=prod`` typos are caught), but everything else only
# runs when ``ENVIRONMENT=production``. The ADMIN_PASSWORD gate is
# enforced later from start.prod.sh / create_admin_user.py where the
# user_count is known; calling validate_production_env without a
# user_count here is intentional.
from app.core.startup_validation import (  # noqa: E402  pylint: disable=wrong-import-position
    validate_database_credentials,
    validate_production_env,
)

# The bundled database credential is checked in every mode: Compose renders an
# empty-password URL when the deployment never set POSTGRES_PASSWORD, and the
# backend must refuse it here rather than fail later inside a connection pool.
validate_database_credentials()
validate_production_env()

# Now proceed with other imports


# Load environment variables
load_dotenv()
load_dotenv(override=True)

# Configure logging — stdout only. Container logs are captured by the
# runtime (docker logs / journald / k8s); writing to a file inside the
# bind-mounted app dir fails under non-root and is redundant.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# PRA-310: capture recent backend logs in a bounded in-memory ring buffer so the
# admin support bundle can include them (stdout logs aren't readable from inside the
# app). Idempotent; single-worker model.
from app.core.log_buffer import install_log_buffer  # noqa: E402

install_log_buffer()

from app.core.access_log_redaction import (  # noqa: E402
    install_access_log_redaction,
    sanitize_url_for_log,
)

# PRA-255: sanitized-error request-id publisher (used by LoggingMiddleware).
from app.core.api_errors import set_request_id  # noqa: E402

# Redact secret query values on both logging paths: the request middleware below
# calls the sanitizer directly, and this filter covers the server's own WebSocket
# upgrade lines, which carry the session ticket in the query string and never
# reach any middleware.
install_access_log_redaction()

logger = logging.getLogger(__name__)


# PRA-180 AUTH-01: the single source of truth for which paths skip the
# JWT-auth floor. Anything NOT matched here must carry a valid access JWT
# (enforced centrally in JWTAuthMiddleware) so a route that forgets its
# ``get_current_user`` dependency is still unreachable without a real token.
# Exposed at module level so the auth-invariant test can assert every route is
# either auth-gated or explicitly public.
PUBLIC_EXACT_PATHS = frozenset(
    {
        "/docs",
        "/redoc",
        "/openapi.json",
        "/auth/login",
        "/auth/register",
        # PRA-216: public read so the login UI can hide signup when an admin
        # has disabled self-registration. No auth, no mutation.
        "/auth/registration-status",
        "/auth/refresh",
        # Logout authenticates via the presented refresh-token secret (same model
        # as /auth/refresh), so it must revoke server-side even when the access
        # token is expired or missing — otherwise a stolen refresh token survives
        # an explicit logout. Revocation is scoped to the exact token value and is
        # idempotent, so a public floor here is safe.
        "/auth/logout",
        "/auth/oidc/status",
        "/auth/oidc/login",
        "/auth/oidc/callback",
        "/health",
        # PRA-151 #19: public CA bundle for agent installers (no cert yet).
        "/agent/ca-bundle",
        # PRA-154 #1c: bootstrap activation-token redemption (token-header auth).
        "/agent/enroll",
        # PRA-154 #1d-b: control-plane-served bootstrap script (no secret).
        "/agent/bootstrap.sh",
    }
)

# Prefix allow-list: these route families do their OWN non-JWT auth.
#   /agent/download/  — pinned-name artifact download (closed allow-list route).
#   /mirrors/*/serve/ — per-(host, mirror) bearer/Basic creds, not JWT.
PUBLIC_PATH_PREFIXES = ("/agent/download/",)


def is_public_path(path: str) -> bool:
    """True when ``path`` is allowed to skip the JWT-auth floor."""
    if path in PUBLIC_EXACT_PATHS:
        return True
    if any(path.startswith(p) for p in PUBLIC_PATH_PREFIXES):
        return True
    # Mirror serve endpoints own their auth + WWW-Authenticate challenge.
    if "/serve/" in path and path.startswith("/mirrors/"):
        return True
    return False


class JWTAuthMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Middleware to handle JWT authentication."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        # Public / non-JWT-auth paths skip the JWT floor (see is_public_path).
        if is_public_path(path):
            return await call_next(request)

        # PRA-180 AUTH-01: fail closed. Every non-allow-listed path must carry a
        # VALID access JWT, not merely a non-empty Authorization header — so a
        # route that forgets its ``get_current_user`` dependency is still
        # unreachable without a real token. Per-route dependencies still do the
        # DB user lookup + role checks; this is the central authn floor.
        from app.core.auth import decode_access_token  # noqa: PLC0415

        auth_header = request.headers.get("Authorization")
        token = None
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication required"},
            )
        try:
            decode_access_token(token)
        except Exception:  # pylint: disable=broad-except
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication credentials"},
            )
        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Middleware to log requests and responses."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start_time = time.time()
        request_id = str(uuid.uuid4())
        # PRA-255: publish the correlation id so route handlers and the sanitized
        # error helper can read it (log correlation + X-Request-ID) without every
        # handler needing a Request parameter.
        request.state.request_id = request_id
        set_request_id(request_id)
        logger.info(
            "Request %s: %s %s",
            request_id,
            request.method,
            sanitize_url_for_log(str(request.url)),
        )
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            logger.info(
                "Response %s: Status %d Process Time: %.3fs",
                request_id,
                response.status_code,
                process_time,
            )
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)
            return response
        except Exception as e:
            logger.error("Request %s failed: %s", request_id, str(e))
            raise


class SecurityHeadersMiddleware(
    BaseHTTPMiddleware
):  # pylint: disable=too-few-public-methods
    """Middleware to add security headers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"

        # Relaxed CSP for Swagger docs pages (CDN scripts + inline)
        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' https://fastapi.tiangolo.com data:;"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; style-src 'self' 'unsafe-inline'"
            )

        return response


from app.core.rate_limit import limiter  # noqa: E402
from app.core.version import get_version  # noqa: E402


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    is_production = os.getenv("ENVIRONMENT") == "production"

    app_instance = FastAPI(
        title="Praxis",
        description="Linux Management System API",
        version=get_version(),
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
        redirect_slashes=False,
    )

    # Rate limiting
    app_instance.state.limiter = limiter
    app_instance.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS - explicit origins from env (no wildcard with credentials)
    cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    cors_origins = [origin.strip() for origin in cors_origins if origin.strip()]
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app_instance.add_middleware(ServerErrorMiddleware)

    # Trusted hosts from env (defaults to localhost for dev)
    trusted_hosts = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
    trusted_hosts = [h.strip() for h in trusted_hosts if h.strip()]
    app_instance.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    app_instance.add_middleware(SecurityHeadersMiddleware)
    app_instance.add_middleware(LoggingMiddleware)
    app_instance.add_middleware(JWTAuthMiddleware)

    # Include routers
    app_instance.include_router(auth_router)
    app_instance.include_router(oidc_router, prefix="/auth/oidc")
    app_instance.include_router(users_router)
    # system_compare_router MUST come before systems_router so /systems/compare
    # is matched before the /systems/{system_id} catch-all path parameter.
    app_instance.include_router(
        system_compare_router,
        prefix="/systems",
        tags=["system-compare"],
    )
    app_instance.include_router(systems_router, prefix="/systems", tags=["systems"])
    app_instance.include_router(
        onboarding_router, prefix="/onboarding", tags=["onboarding"]
    )
    # PRA-155 #2b-b: facts router mounts inside /systems so endpoints
    # land at /systems/{id}/facts/* alongside the rest of the system
    # CRUD surface.
    app_instance.include_router(facts_router, prefix="/systems", tags=["facts"])
    # PRA-156 #3b: lifecycle read endpoint mounts inside /systems so
    # GET /systems/{id}/lifecycle sits next to the facts read.
    app_instance.include_router(lifecycle_router, prefix="/systems", tags=["lifecycle"])
    # PRA-159 #3: POST /systems/{id}/content-profile/apply. Declared
    # BEFORE content_profile_systems_router so the literal /apply
    # subpath matches before the bare /content-profile reads in that
    # router (FastAPI declared-route order).
    app_instance.include_router(
        content_profile_apply_router,
        prefix="/systems",
        tags=["content-profiles"],
    )
    # PRA-159 #1: GET /systems/{id}/content-profile (effective profile
    # resolution returning no_profile|resolved|conflict). Mounted under
    # /systems alongside facts/lifecycle reads.
    app_instance.include_router(
        content_profile_systems_router,
        prefix="/systems",
        tags=["content-profiles"],
    )
    # PRA-156 #3d: fleet-level lifecycle endpoints (/lifecycle/summary,
    # /lifecycle/systems) mount at root, NOT under /systems — they're
    # fleet aggregates, not per-system reads. Two separate routers
    # rather than nesting under /systems so the URLs don't end up as
    # /systems/lifecycle/summary.
    app_instance.include_router(lifecycle_fleet_router, tags=["lifecycle"])
    app_instance.include_router(groups_router, prefix="/groups", tags=["groups"])
    app_instance.include_router(health_router, prefix="/fleet", tags=["fleet"])
    app_instance.include_router(tags_router, prefix="/tags", tags=["tags"])
    app_instance.include_router(bulk_router, prefix="/bulk", tags=["bulk"])
    app_instance.include_router(audits_router, prefix="/audits", tags=["audits"])
    app_instance.include_router(
        fleet_operations_router,
        prefix="/fleet/operations",
        tags=["fleet-operations"],
    )
    app_instance.include_router(
        fleet_access_router,
        prefix="/fleet",
        tags=["fleet-access"],
    )
    app_instance.include_router(
        access_requests_router,
        prefix="/access/requests",
        tags=["access-requests"],
    )
    # PRA-132: access reviews are a paid governance control.
    app_instance.include_router(
        access_reviews_router,
        prefix="/access-reviews",
        tags=["access-reviews"],
        dependencies=[Depends(require_entitlement(ACCESS_ACCESS_REVIEWS))],
    )
    app_instance.include_router(totp_router, prefix="/totp", tags=["totp"])
    app_instance.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
    # PRA-132: session locks + session approvals are paid governance controls.
    app_instance.include_router(
        session_locks_router,
        prefix="/session-locks",
        tags=["session-locks"],
        dependencies=[Depends(require_entitlement(ACCESS_SESSION_LOCKS))],
    )
    app_instance.include_router(
        session_approvals_router,
        prefix="/session-approvals",
        tags=["session-approvals"],
        dependencies=[Depends(require_entitlement(ACCESS_SESSION_APPROVALS))],
    )
    app_instance.include_router(
        recordings_router, prefix="/recordings", tags=["recordings"]
    )
    app_instance.include_router(
        file_transfer_router, prefix="/transfer", tags=["file-transfer"]
    )
    app_instance.include_router(audit_router, prefix="/audit", tags=["audit"])
    app_instance.include_router(packages_router, prefix="/packages", tags=["packages"])
    app_instance.include_router(jobs_router, prefix="/jobs", tags=["jobs"])
    app_instance.include_router(
        notifications_router, prefix="/notifications", tags=["notifications"]
    )
    app_instance.include_router(
        notification_preferences_router,
        prefix="/notification-preferences",
        tags=["notification-preferences"],
    )
    app_instance.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
    app_instance.include_router(
        smart_groups_router, prefix="/smart-groups", tags=["smart-groups"]
    )
    app_instance.include_router(
        baselines_router, prefix="/baselines", tags=["baselines"]
    )
    # PRA-159 #2: mirror serve endpoint. MUST be registered BEFORE
    # mirrors_router so the string ``{slug}`` match wins over the
    # ``{mirror_id}: int`` matches in the CRUD router (FastAPI tries
    # registered routes in order; the int converter fails fast on a
    # slug like "ubuntu-jammy" so the string-pattern route picks it
    # up next, but locking declaration order avoids surprises).
    app_instance.include_router(
        mirror_serve_router,
        prefix="/mirrors/{slug}/serve",
        tags=["mirror-serve"],
    )
    app_instance.include_router(mirrors_router, prefix="/mirrors", tags=["mirrors"])
    app_instance.include_router(
        mirror_upstream_keys_router,
        prefix="/mirror-upstream-keys",
        tags=["mirror-upstream-keys"],
    )
    # PRA-159 #2: per-host mirror serve credential management.
    # Mounted under /systems so paths land at
    # /systems/{system_id}/mirror-serve-credentials/...
    app_instance.include_router(
        mirror_serve_credentials_router,
        prefix="/systems",
        tags=["mirror-serve-credentials"],
    )
    # PRA-159 #1: content channels (composition) and content profiles
    # (host desired source config). Profiles are the host-facing
    # binding object; channels are pure composition.
    app_instance.include_router(
        content_channels_router,
        prefix="/content-channels",
        tags=["content-channels"],
    )
    app_instance.include_router(
        content_profiles_router,
        prefix="/content-profiles",
        tags=["content-profiles"],
    )
    # PRA-160 slice #1: airgap export/import. Slice #1 ships the
    # signing-key bootstrap and a descriptor-only export endpoint;
    # later slices add tar assembly, import, and delta bundles.
    app_instance.include_router(
        airgap_router,
        prefix="/airgap",
        tags=["airgap"],
    )
    # PRA-161 slice 1b: patch policy CRUD. Bindings, resolver, and
    # apply path are deferred to later slices/efforts.
    app_instance.include_router(
        patch_policies_router,
        prefix="/patch/policies",
        tags=["patch-policies"],
    )
    # PRA-162 slice 1: patch rings (canary / pilot / prod) — first-class
    # ring model + triple-source bindings. Resolver + policy-ring binding
    # + gate evaluation are deferred to later PRA-162 slices.
    app_instance.include_router(
        patch_rings_router,
        prefix="/patch/rings",
        tags=["patch-rings"],
    )
    # PRA-161 slice 1d: per-host effective-policy resolver endpoint.
    # Mounted under /systems so the URL shape mirrors the existing
    # /systems/{id}/lifecycle endpoint.
    app_instance.include_router(
        system_patch_policy_router,
        prefix="/systems",
        tags=["system-patch-policy"],
    )
    # PRA-162 slice 2: per-host effective-ring resolver endpoint.
    # Same mount shape as the patch-policy resolver above.
    app_instance.include_router(
        system_patch_ring_router,
        prefix="/systems",
        tags=["system-patch-ring"],
    )
    # PRA-163 slice 4: advisory list / detail / fleet-counts.
    app_instance.include_router(
        patch_advisories_router,
        prefix="/patch/advisories",
        tags=["patch-advisories"],
    )
    # PRA-163 slice 4: per-host advisory list / counts / manual recompute.
    app_instance.include_router(
        system_patch_advisories_router,
        prefix="/systems",
        tags=["system-patch-advisories"],
    )
    # PRA-165 slice 1: compliance policy framework substrate. CRUD,
    # typed check definitions, starter-pack seed, audit emission only.
    # No probe execution, no per-host evidence rows, no dashboard /
    # export / frontend expansion — those land in later slices.
    app_instance.include_router(
        compliance_policies_router,
        prefix="/compliance/policies",
        tags=["compliance-policies"],
    )
    app_instance.include_router(
        compliance_checks_router,
        prefix="/compliance/checks",
        tags=["compliance-checks"],
    )
    app_instance.include_router(
        compliance_starter_pack_router,
        prefix="/compliance/starter-pack",
        tags=["compliance-starter-pack"],
    )
    # PRA-165 Slice 3: per-host evidence read, fleet rollup, JSONL/CSV
    # exports. Read endpoints accept any authenticated user; export
    # endpoints require admin/maintainer.
    app_instance.include_router(
        compliance_systems_router,
        prefix="/compliance/systems",
        tags=["compliance-systems"],
    )
    app_instance.include_router(
        compliance_fleet_router,
        prefix="/compliance/fleet",
        tags=["compliance-fleet"],
    )
    # PRA-132: bulk compliance/evidence exports are paid. Core compliance
    # dashboard, policies, evidence reads, and remediation stay free.
    app_instance.include_router(
        compliance_exports_router,
        prefix="/compliance/exports",
        tags=["compliance-exports"],
        dependencies=[Depends(require_entitlement(COMPLIANCE_BULK_EXPORTS))],
    )
    # PRA-167 Slice 1: non-executing compliance remediation request
    # substrate. Create / list / get / approve / reject / cancel only —
    # approval flips state, never dispatches or runs anything. Execution
    # belongs to later PRA-167 slices.
    app_instance.include_router(
        compliance_remediation_router,
        prefix="/compliance/remediation-requests",
        tags=["compliance-remediation"],
    )
    # PRA-167 Slice 2: non-executing remediation execution-plan preview
    # substrate. The build/get-by-request endpoints live on the existing
    # remediation_router as sub-resources; this flat router exposes
    # list / get-by-id for the dashboard read path. Building a plan
    # never runs anything on the host.
    app_instance.include_router(
        compliance_remediation_plans_router,
        prefix="/compliance/remediation-plans",
        tags=["compliance-remediation-plans"],
    )
    # PRA-167 Slice 4: read-only fleet remediation summary. Per-host
    # remediation inventory is mounted on the existing
    # ``compliance_systems_router`` (already attached above), so this
    # router only carries the fleet rollup endpoint. No execution.
    app_instance.include_router(
        compliance_remediation_fleet_router,
        prefix="/compliance/remediation",
        tags=["compliance-remediation-fleet"],
    )
    # PRA-176 Slice 1: non-executing compliance remediation
    # execution-attempt substrate. Persists durable audit-rows for
    # operator intent to dispatch an acknowledged-ready package
    # plan; the readiness gate is re-checked at write time so a
    # stale UI cannot bypass it. NO host mutation, command
    # execution, dispatch, runner, rollback, or facts/package
    # refresh happens here — later PRA-176 slices add transport
    # selection and dispatch on top of the same row.
    app_instance.include_router(
        compliance_remediation_executions_router,
        prefix="/compliance/remediation-executions",
        tags=["compliance-remediation-executions"],
    )
    # PRA-164 slice 1: dry-run patch update plan substrate. Plan creation,
    # listing, refresh, and cancel only — package selection preview,
    # preflight snapshots, approval integration, and execution land in
    # later slices / PRAs.
    app_instance.include_router(
        patch_update_plans_router,
        prefix="/patch/update-plans",
        tags=["patch-update-plans"],
    )
    # PRA-171 slice 1: execution-run substrate + live-progress read model.
    # Materializes a durable execution row + per-host rows from an
    # approved/scheduled plan. Metadata-only controls (start/pause/resume/
    # cancel) — no package-manager dispatch, SSH, agent ops, package
    # mutation, history mutation, reboot, rollback, mirror mutation, or
    # airgap behavior. Real execution lands in later PRA-171 slices.
    app_instance.include_router(
        patch_executions_router,
        prefix="/patch/update-executions",
        tags=["patch-update-executions"],
    )
    # PRA-178 Slice 2: durable report-run history. Read-only —
    # report-run rows are written by the Slice 1 manual export
    # routes; the scheduler that would write
    # ``triggered_by='system_scheduled'`` rows is intentionally
    # deferred to a later slice.
    app_instance.include_router(
        reports_router,
        prefix="/reports",
        tags=["reports"],
    )
    app_instance.include_router(repos_router, prefix="/repos", tags=["repos"])
    app_instance.include_router(
        credentials_router, prefix="/credentials", tags=["credentials"]
    )
    app_instance.include_router(ssh_router, prefix="/ssh", tags=["ssh"])
    app_instance.include_router(
        ssh_identity_router, prefix="/ssh-identity", tags=["ssh-identity"]
    )
    app_instance.include_router(agent_router, prefix="/agent", tags=["agent"])
    app_instance.include_router(
        activation_tokens_router,
        prefix="/agent/activation-tokens",
        tags=["agent"],
    )
    app_instance.include_router(agent_enroll_router, prefix="/agent", tags=["agent"])
    app_instance.include_router(agent_bootstrap_router, prefix="/agent", tags=["agent"])
    app_instance.include_router(
        ssh_security_router, prefix="/ssh-security", tags=["ssh-security"]
    )
    app_instance.include_router(vault_router, prefix="/vault", tags=["vault"])
    # PRA-132: the command approval queue / multi-approval flow is paid.
    app_instance.include_router(
        command_approvals_router,
        prefix="/command-approvals",
        tags=["command-approvals"],
        dependencies=[Depends(require_entitlement(COMMANDS_APPROVALS))],
    )
    app_instance.include_router(
        command_execution_router,
        prefix="/command-execution",
        tags=["command-execution"],
    )
    app_instance.include_router(
        diagnostics_router,
        prefix="/diagnostics",
        tags=["diagnostics"],
    )
    app_instance.include_router(
        command_whitelist_router,
        prefix="/command-whitelist",
        tags=["command-whitelist"],
    )
    app_instance.include_router(
        connection_settings_router,
        prefix="/connection-settings",
        tags=["connection-settings"],
    )
    app_instance.include_router(
        command_result_processing_router,
        prefix="/command-results",
        tags=["command-results"],
    )
    app_instance.include_router(
        system_status_router,
        prefix="/system-status",
        tags=["system-status"],
    )
    app_instance.include_router(
        package_reports_router,
        prefix="/package-reports",
        tags=["package-reports"],
    )
    app_instance.include_router(
        activity_feed_router,
        prefix="/activity",
        tags=["activity-feed"],
    )
    app_instance.include_router(
        analytics_router,
        prefix="/analytics",
        tags=["analytics"],
    )
    app_instance.include_router(
        export_router,
        prefix="/export",
        tags=["export"],
    )
    app_instance.include_router(
        views_router,
        prefix="/views",
        tags=["views"],
    )
    app_instance.include_router(
        maintenance_windows_router,
        prefix="/maintenance-windows",
        tags=["maintenance-windows"],
    )
    app_instance.include_router(
        app_settings_router,
        prefix="/app-settings",
        tags=["app-settings"],
    )
    # PRA-132: read-only edition/entitlement surface for the frontend.
    app_instance.include_router(
        edition_router,
        prefix="/edition",
        tags=["edition"],
    )

    # PRA-132: register the optional paid ``praxis_ee`` extension if present.
    # Absent praxis_ee -> free edition (the default). A present-but-broken
    # extension raises EELoaderError and fails startup loudly rather than
    # silently downgrading a paid deployment to free.
    load_ee(app=app_instance)

    @app_instance.on_event("startup")
    async def startup_event():
        """Start the background scheduler on application startup."""
        # PRA-310 supportability: log DB reachability + schema head at startup so a
        # support bundle captures whether the app came up against a migrated DB.
        # Best-effort — a diagnostic line must never block startup.
        if not os.getenv("TESTING"):
            try:
                from sqlalchemy import text as _sql_text

                from app.core.support_logging import log_support_event
                from app.db.session import SessionLocal as _SessionLocal

                _db = _SessionLocal()
                try:
                    _db.execute(_sql_text("SELECT 1"))
                    head = _db.execute(
                        _sql_text("SELECT version_num FROM alembic_version")
                    ).scalar()
                    log_support_event(
                        logger,
                        "db.startup",
                        outcome="ready",
                        reconcile_state=str(head),
                    )
                finally:
                    _db.close()
            except Exception as e:  # pylint: disable=broad-except
                logger.error("db.startup check failed: %s", str(e))

        # PRA-133: hydrate the entitlement registry from a stored offline license
        # so a restarted install stays licensed. Read-only + a no-op when no
        # token is stored, so a stock free install (and the test harness) is
        # untouched. Never let this block startup.
        try:
            from app.db.session import SessionLocal
            from app.services import license_service

            db = SessionLocal()
            try:
                license_service.hydrate_registry(db)
                # Online license refresh: if this install is connected and its
                # license is near expiry, try to renew it now. Best-effort and
                # non-fatal — it never blocks startup (skips entirely unless a
                # refresh token is configured AND expiry is within the window),
                # never clears/downgrades the current license, and swallows all
                # errors internally.
                license_service.maybe_auto_refresh(db)
            finally:
                db.close()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("License hydration failed: %s", str(e))

        try:
            from app.services.scheduler_service import scheduler_service

            scheduler_service.start()
            logger.info("Background scheduler started")
        except Exception as e:
            logger.error("Failed to start scheduler: %s", str(e))

        # PRA-301: start the single Prometheus scrape listener (backend:9090) for the
        # supported single-worker deployment. Explicit + idempotent (no import side
        # effect). Skipped under TESTING so the test harness never binds the port,
        # and best-effort so a bind failure never blocks startup.
        if not os.getenv("TESTING"):
            try:
                from app.db.session import start_metrics_server

                if start_metrics_server():
                    logger.info("Prometheus metrics listener started on :9090")
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("Failed to start metrics listener: %s", str(e))

    @app_instance.on_event("shutdown")
    async def shutdown_event():
        """Stop the background scheduler on application shutdown."""
        try:
            from app.services.scheduler_service import scheduler_service

            scheduler_service.stop()
            logger.info("Background scheduler stopped")
        except Exception as e:
            logger.error("Failed to stop scheduler: %s", str(e))

    @app_instance.get("/health")
    async def health_check():
        """Endpoint for health check."""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": app_instance.version,
        }

    return app_instance


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
