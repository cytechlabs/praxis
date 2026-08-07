"""Public-core loader boundary for the optional ``praxis_ee`` extension.

Praxis core is fully functional on its own. Paid builds add a **separate,
closed-source** ``praxis_ee`` Python package (never in this repository) that
registers paid entitlements at startup. This module is the only seam between the
two: it tries to import ``praxis_ee`` and call its ``register_ee(...)`` hook.

Contract for ``praxis_ee``::

    def register_ee(*, registry, app=None, db_session_factory=None, config=None):
        '''Inspect the local license and grant paid entitlements.

        Called once at startup. Implementations read whatever license/state they
        manage and call registry.grant(...) / registry.enable_enterprise(...) /
        registry.set_edition(...) accordingly. With no valid license the hook is
        expected to grant nothing, leaving Praxis in the free edition.
        '''

Failure policy:

* ``praxis_ee`` **absent** -> free edition, no error. This is the stock
  open-source build and the common case.
* ``praxis_ee`` **present but broken** (no callable ``register_ee``, or the hook
  raises) -> :class:`EELoaderError`. A bundled paid image ships ``praxis_ee``, so
  a broken hook is a real deployment bug and must fail loudly rather than
  silently downgrade a paying customer to free with no signal.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

EE_MODULE_NAME = "praxis_ee"
EE_REGISTER_ATTR = "register_ee"


class EELoaderError(RuntimeError):
    """Raised when ``praxis_ee`` is present but its loader contract is broken."""


def load_ee(
    app: Any = None,
    *,
    registry: Optional[Any] = None,
    db_session_factory: Optional[Callable[..., Any]] = None,
    config: Optional[Any] = None,
) -> bool:
    """Load and register the optional ``praxis_ee`` extension.

    Returns ``True`` when an EE package registered (the edition it decided on may
    still be free if unlicensed), ``False`` for a stock free build with no EE
    package. Raises :class:`EELoaderError` when ``praxis_ee`` is importable but
    its ``register_ee`` contract is broken.
    """
    if registry is None:
        # Imported lazily so ``app.ee`` has no import-time dependency on the
        # entitlement registry beyond the default singleton.
        from app.core.entitlements import registry as default_registry

        registry = default_registry

    try:
        ee_module = importlib.import_module(EE_MODULE_NAME)
    except ModuleNotFoundError as exc:
        # Only the *top-level package being absent* means free edition. A
        # ModuleNotFoundError whose missing module is something else was raised
        # from *inside* an installed praxis_ee (e.g. a missing dependency) — that
        # is a broken build and must fail loud, not silently downgrade to free.
        if exc.name == EE_MODULE_NAME:
            logger.info(
                "%s not installed; running in the free/core edition", EE_MODULE_NAME
            )
            return False
        raise EELoaderError(
            f"{EE_MODULE_NAME} is installed but failed to import "
            f"(missing {exc.name!r}); refusing to silently run as free edition"
        ) from exc
    except ImportError as exc:
        # Any other import-time failure inside an installed praxis_ee.
        raise EELoaderError(
            f"{EE_MODULE_NAME} is installed but failed to import; "
            "refusing to silently run as free edition"
        ) from exc

    register = getattr(ee_module, EE_REGISTER_ATTR, None)
    if not callable(register):
        # Present but broken contract -> fail loud.
        raise EELoaderError(
            f"{EE_MODULE_NAME} is installed but has no callable "
            f"{EE_REGISTER_ATTR}(); refusing to silently run as free edition"
        )

    try:
        register(
            registry=registry,
            app=app,
            db_session_factory=db_session_factory,
            config=config,
        )
    except Exception as exc:  # pragma: no cover - exercised via a broken fake
        raise EELoaderError(
            f"{EE_MODULE_NAME}.{EE_REGISTER_ATTR}() raised during registration"
        ) from exc

    logger.info(
        "%s registered; edition=%s", EE_MODULE_NAME, getattr(registry, "edition", "?")
    )
    return True
