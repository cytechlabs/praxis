"""PRA-155 #2b-b: scheduler entry for periodic facts collection.

Runs once per scheduler tick (every 30 min); for each managed host,
refreshes facts via SSH if the existing ``host_facts.collected_at`` is
older than ``FACTS_REFRESH_INTERVAL_SECONDS`` (or there's no row at
all). Already-fresh hosts are skipped — no SSH connection, no audit
churn.

The sweep itself is the unit of concurrency control. APScheduler's
``max_instances=1`` on the job prevents two sweeps from running
simultaneously, so per-host concurrency isn't an issue (no host gets
two SSH probes at once from the scheduler). Manual ``POST /systems/
{id}/facts/refresh`` requests can race a sweep — that's safe because
``FactsService.ingest`` is upsert + stale-write rejected; the newer
``collected_at`` wins and the loser becomes either a noop_empty or
rejected_stale outcome with an audit row.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict

from sqlalchemy.orm import Session

from ..db.models import HostFacts, System
from . import ssh_facts_collector_service

logger = logging.getLogger(__name__)


# Locked default per the PRA-155 #2b-b design lock — 6h. Staleness
# *display* in #2c uses 24h independently; this is the **refresh**
# cadence, not the staleness threshold. App-settings configurability
# lives in #2c only if cheap; for now the constant is the contract.
FACTS_REFRESH_INTERVAL_SECONDS = 6 * 60 * 60


def run_facts_refresh_sweep(db: Session) -> Dict[str, int]:
    """Walk every Active host; refresh facts via SSH where stale.

    Returns a stats dict suitable for the scheduler log line:
        {"considered": N, "skipped_fresh": N, "refreshed": N,
         "ssh_failed": N}
    """
    stats = {
        "considered": 0,
        "skipped_fresh": 0,
        "refreshed": 0,
        "ssh_failed": 0,
    }
    threshold = datetime.utcnow() - timedelta(seconds=FACTS_REFRESH_INTERVAL_SECONDS)

    # Left-join host_facts so hosts with no row at all also surface.
    # Active-only filter mirrors the rest of the fleet sweepers — a
    # decommissioned host shouldn't get nightly SSH probes.
    rows = (
        db.query(System, HostFacts)
        .outerjoin(HostFacts, HostFacts.system_id == System.id)
        .filter(System.status == "Active")
        .all()
    )

    for system, facts_row in rows:
        stats["considered"] += 1
        if (
            facts_row is not None
            and facts_row.collected_at is not None
            and facts_row.collected_at >= threshold
        ):
            stats["skipped_fresh"] += 1
            continue
        try:
            ssh_facts_collector_service.collect_and_ingest(db, system_id=system.id)
            stats["refreshed"] += 1
        except ssh_facts_collector_service.SshFactsCollectionError as exc:
            stats["ssh_failed"] += 1
            logger.info(
                "facts sweep: ssh failed for system_id=%s: %s",
                system.id,
                exc,
            )
        except Exception:  # pylint: disable=broad-except
            # Belt-and-suspenders: any other unexpected failure must
            # not abort the rest of the sweep. FactsService.ingest's
            # own exceptions land here.
            stats["ssh_failed"] += 1
            logger.exception(
                "facts sweep: unexpected error for system_id=%s",
                system.id,
            )

    return stats
