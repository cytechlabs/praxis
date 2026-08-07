"""Free-space gate for the mirror engine (PRA-157 #2a).

Two layers, both must pass before a sync can start:

  1. **Global reserve** (mandatory). ``free_bytes`` on the volume
     hosting ``PRAXIS_MIRROR_ROOT`` must exceed
     ``max(PRAXIS_MIRROR_MIN_FREE_BYTES,
          PRAXIS_MIRROR_MIN_FREE_PERCENT * volume_capacity / 100)``.
     Per the design lock, gating on the larger of the two scales
     sensibly across tiny dev volumes and multi-TB prod volumes.
  2. **Per-mirror estimate** (best-effort). If the engine can produce
     an estimate, ``free_bytes`` must exceed
     ``estimate * SAFETY_FACTOR``. If no estimate is available,
     refuse only when the mirror has ``disk_budget_bytes`` set AND
     the conservative fallback (``current_disk_bytes * 1.5``) would
     breach available space — otherwise allow the sync with the
     ``estimate_unavailable`` flag set on the run row.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .mirror_paths import (
    DEFAULT_MIN_FREE_BYTES,
    DEFAULT_MIN_FREE_PERCENT,
    min_free_bytes,
    min_free_percent,
    mirror_root,
)

logger = logging.getLogger(__name__)

# Safety factor multiplier on per-mirror estimates. 2.0 = "want
# twice the estimate available so an underestimate doesn't catch
# us out." Conservative; can be tuned via env later if it pinches.
DEFAULT_ESTIMATE_SAFETY_FACTOR = 2.0

# Conservative fallback multiplier when no estimate is available
# but the mirror has a disk_budget_bytes set: assume the next sync
# could grow the on-disk footprint by 50% over current. Caps over-
# commit while still letting first syncs proceed when there's no
# prior history to base an estimate on.
CONSERVATIVE_FALLBACK_MULTIPLIER = 1.5


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str  # human-readable; "" on allow, populated on refuse
    estimate_unavailable: bool


def _global_min_free(capacity_bytes: int) -> int:
    return max(
        min_free_bytes(),
        (min_free_percent() * capacity_bytes) // 100,
    )


def check_free_space_gate(
    *,
    estimate_bytes: Optional[int],
    mirror_disk_budget: Optional[int],
    current_disk_bytes: int,
    safety_factor: float = DEFAULT_ESTIMATE_SAFETY_FACTOR,
    root: Optional[Path] = None,
) -> GateDecision:
    """Decide whether a sync is allowed to start given current disk state.

    ``estimate_bytes`` may be ``None`` if the engine couldn't compute
    a dry-run estimate (first sync, dry-run failed, etc.). The
    decision still proceeds — see the per-mirror best-effort path.
    """
    target = root or mirror_root()
    # ``target`` may not exist yet on a brand-new install. Fall back
    # to the parent that does — disk usage is whole-volume anyway.
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)

    capacity = usage.total
    free = usage.free
    global_floor = _global_min_free(capacity)

    if free < global_floor:
        return GateDecision(
            allowed=False,
            reason=(
                f"global free-space reserve breached: free={free} bytes "
                f"< floor={global_floor} bytes "
                f"(volume capacity={capacity}, "
                f"PRAXIS_MIRROR_MIN_FREE_BYTES default={DEFAULT_MIN_FREE_BYTES}, "
                f"PRAXIS_MIRROR_MIN_FREE_PERCENT default="
                f"{DEFAULT_MIN_FREE_PERCENT})"
            ),
            estimate_unavailable=estimate_bytes is None,
        )

    if estimate_bytes is not None:
        required = int(estimate_bytes * safety_factor)
        if free < required:
            return GateDecision(
                allowed=False,
                reason=(
                    f"estimate gate breached: free={free} bytes "
                    f"< estimate * {safety_factor} = {required} bytes "
                    f"(estimate={estimate_bytes})"
                ),
                estimate_unavailable=False,
            )
        return GateDecision(allowed=True, reason="", estimate_unavailable=False)

    # No estimate: best-effort path. If the operator set a per-mirror
    # disk budget, they care about size — apply a conservative
    # fallback. Otherwise let the sync proceed with the warning flag.
    if mirror_disk_budget is not None:
        fallback = int(
            max(current_disk_bytes, mirror_disk_budget // 4)
            * CONSERVATIVE_FALLBACK_MULTIPLIER
        )
        if free < fallback:
            return GateDecision(
                allowed=False,
                reason=(
                    f"estimate unavailable + per-mirror budget set; "
                    f"conservative fallback exceeded: free={free} bytes "
                    f"< fallback={fallback} bytes "
                    f"(current_disk={current_disk_bytes}, "
                    f"budget={mirror_disk_budget})"
                ),
                estimate_unavailable=True,
            )

    return GateDecision(allowed=True, reason="", estimate_unavailable=True)


__all__ = [
    "GateDecision",
    "check_free_space_gate",
    "DEFAULT_ESTIMATE_SAFETY_FACTOR",
    "CONSERVATIVE_FALLBACK_MULTIPLIER",
]
