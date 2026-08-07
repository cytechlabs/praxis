"""Edition / entitlement registry for Praxis (public core).

Praxis ships open-core. This module is the single source of truth for the 1.0
edition matrix and the entitlement keys that separate the free/core edition from
the paid edition. **Free is the default**: the registry starts with no paid
entitlements active, so a stock open-source build (no ``praxis_ee`` package)
runs as the free edition.

Paid entitlements are activated only by the optional ``praxis_ee`` extension
through the ``app.ee`` loader boundary (see :mod:`app.ee.loader`). A bundled
build with ``praxis_ee`` present but no valid license must also behave as free
mode — that decision lives in the closed EE code, which simply declines to grant
any entitlement here.

The registry itself never reads a license file, database, or network: PRA-132
established it, and PRA-133's :mod:`app.services.license_service` validates an
offline license and hydrates this registry via :meth:`apply_license`. Runtime
expiry is enforced here (reads fall back to free once ``expires_at`` passes) so a
long-running process deactivates paid state without a restart.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, status

# --------------------------------------------------------------------------- #
# Edition names + explicit 1.0 paid entitlement keys.
# --------------------------------------------------------------------------- #

EDITION_FREE = "free"
EDITION_ENTERPRISE = "enterprise"

# License tiers (PRA-133). ``free`` is the unlicensed default; the paid tiers are
# unlocked by a valid license. 1.0 self-serve caps are Pro=50, Team=200,
# Business=500; Enterprise is sales-assisted with an explicit negotiated cap.
TIER_FREE = "free"
TIER_PRO = "pro"
TIER_TEAM = "team"
TIER_BUSINESS = "business"
TIER_ENTERPRISE = "enterprise"
PAID_TIERS: frozenset = frozenset({TIER_PRO, TIER_TEAM, TIER_BUSINESS, TIER_ENTERPRISE})
ALL_TIERS: frozenset = frozenset({TIER_FREE}) | PAID_TIERS

# License state for the currently-stored token (surfaced to operators).
LICENSE_STATE_NONE = "none"  # no license applied -> free
LICENSE_STATE_ACTIVE = "active"  # valid, unexpired, instance-bound
LICENSE_STATE_EXPIRED = "expired"
LICENSE_STATE_INVALID = "invalid"  # bad signature / unsupported / rejected
LICENSE_STATE_WRONG_INSTANCE = "wrong_instance"
LICENSE_STATE_MALFORMED = "malformed"

# Scale.
HOSTS_OVER_FREE_CAP = "hosts.over_free_cap"
# Governance / access controls.
ACCESS_SESSION_LOCKS = "access.session_locks"
ACCESS_SESSION_APPROVALS = "access.session_approvals"
ACCESS_ACCESS_REVIEWS = "access.access_reviews"
COMMANDS_APPROVALS = "commands.approvals"
COMMANDS_METRICS = "commands.metrics"
COMPLIANCE_BULK_EXPORTS = "compliance.bulk_exports"
REPORTS_SCHEDULED_EXPORTS = "reports.scheduled_exports"

# The full, closed set of paid entitlement keys 1.0 recognizes. Granting a key
# outside this set is a programming error (a typo in EE registration should fail
# loudly rather than silently unlock nothing).
PAID_ENTITLEMENTS: frozenset = frozenset(
    {
        HOSTS_OVER_FREE_CAP,
        ACCESS_SESSION_LOCKS,
        ACCESS_SESSION_APPROVALS,
        ACCESS_ACCESS_REVIEWS,
        COMMANDS_APPROVALS,
        COMMANDS_METRICS,
        COMPLIANCE_BULK_EXPORTS,
        REPORTS_SCHEDULED_EXPORTS,
    }
)

# Free/core managed-host cap. The paid ``hosts.over_free_cap`` entitlement lifts
# it. The cap value is surfaced for operator awareness in 1.0; the creation-time
# enforcement + license-driven cap lands with the license spine (PRA-133).
FREE_HOST_CAP = 15


class EntitlementError(ValueError):
    """Raised when the registry is asked to grant an unknown entitlement key."""


class EntitlementRegistry:
    """Process-wide, thread-safe holder of the active edition + entitlements.

    Deterministic and dependency-free: it holds a set of active paid entitlement
    keys plus a small amount of edition metadata. It never reads a license, a
    database, or the network — that is the EE extension's job. Everything here
    defaults to the free edition.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: set = set()
        self._edition: str = EDITION_FREE
        # ``None`` is an internal unlimited sentinel used by tests/operator
        # harnesses. Issued paid licenses must carry a numeric host cap.
        self._host_cap: Optional[int] = FREE_HOST_CAP
        self._issued_to: Optional[str] = None
        # License metadata (PRA-133). None/"none" until a valid license applies.
        self._tier: str = TIER_FREE
        self._license_state: str = LICENSE_STATE_NONE
        self._expires_at: Optional[str] = None
        self._license_id: Optional[str] = None

    # -- mutation (EE / license / tests) ---------------------------------- #

    def reset(self) -> None:
        """Return to the pristine free edition. Used by EE re-registration and
        by tests to assert free-mode behavior."""
        with self._lock:
            self._active = set()
            self._edition = EDITION_FREE
            self._host_cap = FREE_HOST_CAP
            self._issued_to = None
            self._tier = TIER_FREE
            self._license_state = LICENSE_STATE_NONE
            self._expires_at = None
            self._license_id = None

    def grant(self, key: str) -> None:
        """Activate a single paid entitlement. Unknown keys fail loudly."""
        if key not in PAID_ENTITLEMENTS:
            raise EntitlementError(f"unknown entitlement key: {key!r}")
        with self._lock:
            self._active.add(key)

    def grant_many(self, keys) -> None:
        for key in keys:
            self.grant(key)

    def enable_enterprise(self) -> None:
        """Convenience for a fully-entitled, unlimited-host edition (every paid
        key active).

        Used by the EE extension when a valid unlimited license is present and by
        the test harness so pre-existing feature tests exercise real behavior
        (including creating more than the free host cap).
        """
        with self._lock:
            self._active = set(PAID_ENTITLEMENTS)
            self._edition = EDITION_ENTERPRISE
            self._host_cap = None  # unlimited
            self._tier = TIER_ENTERPRISE
            self._license_state = LICENSE_STATE_ACTIVE

    def apply_license(
        self,
        *,
        tier: str,
        host_cap: Optional[int],
        entitlements,
        issued_to: Optional[str],
        expires_at: Optional[str],
        license_id: Optional[str] = None,
    ) -> None:
        """Hydrate the registry from a validated license. Only recognized paid
        keys are activated; paid licenses must carry a numeric host cap."""
        with self._lock:
            self._active = {e for e in entitlements if e in PAID_ENTITLEMENTS}
            self._edition = tier
            self._host_cap = host_cap
            self._issued_to = issued_to
            self._tier = tier
            self._expires_at = expires_at
            self._license_id = license_id
            self._license_state = LICENSE_STATE_ACTIVE

    def set_edition(self, edition: str) -> None:
        with self._lock:
            self._edition = edition

    def set_host_cap(self, host_cap: Optional[int]) -> None:
        with self._lock:
            self._host_cap = host_cap

    def set_issued_to(self, issued_to: Optional[str]) -> None:
        with self._lock:
            self._issued_to = issued_to

    def set_license_state(self, state: str) -> None:
        with self._lock:
            self._license_state = state

    # -- reads ------------------------------------------------------------ #

    def _expired_locked(self) -> bool:
        """True when an active license's ``expires_at`` has passed. Caller holds
        the lock. Runtime expiry is enforced here so a long-running process
        deactivates paid state the moment the license lapses — no restart or
        re-hydrate required."""
        if self._license_state != LICENSE_STATE_ACTIVE or not self._expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self._expires_at)
        except ValueError:
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp

    def is_active(self, key: str) -> bool:
        with self._lock:
            if self._expired_locked():
                return False
            return key in self._active

    @property
    def edition(self) -> str:
        with self._lock:
            return EDITION_FREE if self._expired_locked() else self._edition

    @property
    def host_cap(self) -> Optional[int]:
        """Effective host cap. ``None`` is reserved for internal unlimited mode;
        paid licenses use numeric caps. Falls back to the free cap once expired."""
        with self._lock:
            return FREE_HOST_CAP if self._expired_locked() else self._host_cap

    @property
    def issued_to(self) -> Optional[str]:
        # Kept for display even when expired ("was issued to ...").
        with self._lock:
            return self._issued_to

    @property
    def tier(self) -> str:
        with self._lock:
            return TIER_FREE if self._expired_locked() else self._tier

    @property
    def license_state(self) -> str:
        with self._lock:
            return (
                LICENSE_STATE_EXPIRED if self._expired_locked() else self._license_state
            )

    @property
    def expires_at(self) -> Optional[str]:
        with self._lock:
            return self._expires_at

    @property
    def license_id(self) -> Optional[str]:
        with self._lock:
            return self._license_id

    def active_entitlements(self) -> List[str]:
        with self._lock:
            if self._expired_locked():
                return []
            return sorted(self._active)

    def entitlement_map(self) -> Dict[str, bool]:
        """Every recognized paid key -> whether it is active. Stable shape for
        the frontend so a locked control can be rendered for each key."""
        with self._lock:
            active = set() if self._expired_locked() else self._active
        return {key: (key in active) for key in sorted(PAID_ENTITLEMENTS)}


# Process-wide singleton. Import and use this; construct new registries only in
# isolated unit tests.
registry = EntitlementRegistry()


def is_entitled(key: str) -> bool:
    """True when ``key`` is an active paid entitlement in the current edition."""
    return registry.is_active(key)


def _entitlement_error(key: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=(
            f"This feature requires a paid Praxis edition ({key}). "
            "The free edition includes the full core fleet, patch, "
            "content, and compliance surfaces; this control is part of "
            "the paid governance/scale add-on."
        ),
    )


def assert_entitled(key: str) -> None:
    """Raise **HTTP 402 Payment Required** if ``key`` is not active.

    For **service-layer** gating where a FastAPI dependency isn't available — a
    service reached indirectly (e.g. a paid workflow triggered from an otherwise
    free route) should reject with the same 402 contract as the route-level
    :func:`require_entitlement` dependency.
    """
    if not registry.is_active(key):
        raise _entitlement_error(key)


def require_entitlement(key: str):
    """Dependency factory that blocks a route unless ``key`` is entitled.

    Mirrors :func:`app.core.auth.require_role`. Returns **HTTP 402 Payment
    Required** (not 403) so a paid-feature block is distinguishable from an
    authorization failure — the frontend renders an upgrade/locked state on 402.

    Usage::

        @router.post(
            "/schedules",
            dependencies=[Depends(require_entitlement(REPORTS_SCHEDULED_EXPORTS))],
        )

    or at the router mount::

        app.include_router(
            session_locks_router,
            prefix="/session-locks",
            dependencies=[Depends(require_entitlement(ACCESS_SESSION_LOCKS))],
        )
    """

    def checker() -> None:
        assert_entitled(key)

    return checker


def edition_snapshot(host_count: Optional[int] = None) -> Dict[str, object]:
    """Read-only edition + entitlement summary for the ``/edition`` endpoint.

    ``host_count`` is optional so the registry stays DB-free; the route supplies
    the live count. ``hosts_over_cap`` is only meaningful once a count is given.
    """
    cap = registry.host_cap
    snapshot: Dict[str, object] = {
        "edition": registry.edition,
        "entitlements": registry.entitlement_map(),
        "host_cap": cap,  # None is internal unlimited mode.
        "issued_to": registry.issued_to,
        "tier": registry.tier,
        "license_state": registry.license_state,
        "expires_at": registry.expires_at,
        "license_id": registry.license_id,
    }
    if host_count is not None:
        # ``cap is None`` is internal unlimited mode -> never over cap.
        over_cap = cap is not None and host_count > cap
        snapshot["host_count"] = host_count
        snapshot["hosts_over_cap"] = over_cap
    return snapshot


# Re-export Depends so route modules can write
# ``dependencies=[require_entitlement(KEY)]``-style wiring without importing
# fastapi.Depends separately when they already import from here.
__all__ = [
    "EDITION_FREE",
    "EDITION_ENTERPRISE",
    "HOSTS_OVER_FREE_CAP",
    "ACCESS_SESSION_LOCKS",
    "ACCESS_SESSION_APPROVALS",
    "ACCESS_ACCESS_REVIEWS",
    "COMMANDS_APPROVALS",
    "COMMANDS_METRICS",
    "COMPLIANCE_BULK_EXPORTS",
    "REPORTS_SCHEDULED_EXPORTS",
    "PAID_ENTITLEMENTS",
    "FREE_HOST_CAP",
    "TIER_FREE",
    "TIER_PRO",
    "TIER_TEAM",
    "TIER_BUSINESS",
    "PAID_TIERS",
    "ALL_TIERS",
    "LICENSE_STATE_NONE",
    "LICENSE_STATE_ACTIVE",
    "LICENSE_STATE_EXPIRED",
    "LICENSE_STATE_INVALID",
    "LICENSE_STATE_WRONG_INSTANCE",
    "LICENSE_STATE_MALFORMED",
    "EntitlementError",
    "EntitlementRegistry",
    "registry",
    "is_entitled",
    "assert_entitled",
    "require_entitlement",
    "edition_snapshot",
    "Depends",
]
