"""PRA-309 single-worker scaling harness — 500-host envelope measurement.

Measures the DB-bound / dispatch-bound contention paths that actually scale with the
managed-host count on the intentionally single-worker Praxis 1.0 backend, WITHOUT
requiring 500 real VMs. It seeds N synthetic ``System`` rows (marked, cleaned up) and
measures, against the REAL production engine + connection pool
(``pool_size=20, max_overflow=10`` -> 30 max connections):

  * fleet read aggregates   — HealthService dashboard/health GROUP-BY queries an admin
                              UI / the scheduler hit every cycle;
  * reconcile sweep         — the periodic access-control convergence sweep
                              (ThreadPoolExecutor, 8 workers, one Session each), run
                              over ONLY the seeded ids so it never SSHes a real host;
  * DB pool saturation      — concurrent DB-bound ops at 1..2x the pool ceiling, to
                              show the single process's connection-pool envelope
                              (latency + pool_timeout failures past 30 concurrent).

What it deliberately does NOT simulate: real agent tunnels / interactive SSH sessions.
Those are PROCESS-LOCAL and bounded by concurrent-session count, not by host count (see
the assessment doc). This harness measures the fleet-job / request envelope; the
interactive-session envelope is assessed analytically + with a small real subset.

Run inside the backend container (has the app + DB):
    docker compose run --rm --no-deps backend \
        python /app/../scripts/scaling/pra309_load_harness.py --hosts 500 --json out.json
(or mount the repo and point at scripts/scaling/pra309_load_harness.py)

Safety: every seeded row is prefixed ``pra309load-`` and removed on exit unless --keep.
The reconcile sweep runs only over seeded ids, so real Active hosts are never touched.
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone

from sqlalchemy.exc import TimeoutError as SAPoolTimeout

from app.db.models import Credential, Distro, Group, System
from app.db.session import SessionLocal, engine
from app.services import fleet_reconciliation_service as frs
from app.services.health_service import HealthService

MARK = "pra309load-"


def _p(values):
    values = sorted(values)
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min_ms": round(values[0] * 1000, 2),
        "p50_ms": round(statistics.median(values) * 1000, 2),
        "p95_ms": round(values[int(len(values) * 0.95) - 1] * 1000, 2),
        "max_ms": round(values[-1] * 1000, 2),
        "mean_ms": round(statistics.fmean(values) * 1000, 2),
    }


# --------------------------------------------------------------------- seeding


def _ensure_prereqs(db):
    distro = db.query(Distro).filter(Distro.name == MARK + "distro").first()
    if not distro:
        distro = Distro(
            name=MARK + "distro",
            version="1.0",
            release_date=date(2024, 1, 1),
            end_of_life_date=date(2030, 1, 1),
        )
        db.add(distro)
    group = db.query(Group).filter(Group.name == MARK + "group").first()
    if not group:
        group = Group(name=MARK + "group")
        db.add(group)
    cred = db.query(Credential).filter(Credential.name == MARK + "cred").first()
    if not cred:
        cred = Credential(name=MARK + "cred", auth_method="ssh_key")
        db.add(cred)
    db.commit()
    return distro.id, group.id, cred.id


def seed(n):
    db = SessionLocal()
    try:
        distro_id, group_id, cred_id = _ensure_prereqs(db)
        existing = db.query(System).filter(System.hostname.like(MARK + "%")).count()
        to_add = n - existing
        if to_add > 0:
            now = datetime.now(timezone.utc)
            rows = [
                {
                    "hostname": f"{MARK}{i:05d}",
                    "ip_address": f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}",
                    "distro_id": distro_id,
                    "os_version": "1.0",
                    "status": "Active",
                    "group_id": group_id,
                    "credentials_id": cred_id,
                    "registered_at": now,
                    "created_at": now,
                    "updated_at": now,
                }
                for i in range(existing, existing + to_add)
            ]
            db.bulk_insert_mappings(System, rows)
            db.commit()
        ids = [
            r[0]
            for r in db.query(System.id).filter(System.hostname.like(MARK + "%")).all()
        ]
        return ids
    finally:
        db.close()


def cleanup():
    db = SessionLocal()
    try:
        db.query(System).filter(System.hostname.like(MARK + "%")).delete(
            synchronize_session=False
        )
        for model, field, val in (
            (Distro, Distro.name, MARK + "distro"),
            (Group, Group.name, MARK + "group"),
            (Credential, Credential.name, MARK + "cred"),
        ):
            db.query(model).filter(field == val).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ----------------------------------------------------------------- measurements


def measure_reads(iterations):
    db = SessionLocal()
    try:
        svc = HealthService(db)
        # warm up (query plan / caches)
        svc.get_fleet_dashboard()
        svc.get_fleet_health()
        dash, health = [], []
        for _ in range(iterations):
            t = time.perf_counter()
            svc.get_fleet_dashboard()
            dash.append(time.perf_counter() - t)
            t = time.perf_counter()
            svc.get_fleet_health()
            health.append(time.perf_counter() - t)
        return {"get_fleet_dashboard": _p(dash), "get_fleet_health": _p(health)}
    finally:
        db.close()


def measure_reconcile(ids, max_workers=8):
    """Mirror reconcile_all's execution shape over ONLY the seeded ids (never touches
    real hosts). Converged/no-grant hosts -> DB-read-only per host = steady-state cost.
    """
    t = time.perf_counter()
    per_host = []
    errors = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_timed_reconcile_one, sid): sid for sid in ids}
        for fut in as_completed(futures):
            dt, err = fut.result()
            per_host.append(dt)
            errors += err
    wall = time.perf_counter() - t
    return {
        "hosts": len(ids),
        "max_workers": max_workers,
        "wall_s": round(wall, 3),
        "hosts_per_s": round(len(ids) / wall, 1) if wall else None,
        "per_host": _p(per_host),
        "errors": errors,
    }


def _timed_reconcile_one(sid):
    t = time.perf_counter()
    res = frs._reconcile_one_in_worker(sid)
    return time.perf_counter() - t, res.get("errors", 0)


def measure_pool_saturation(concurrencies, ops_per_thread=10):
    """At each concurrency C, C threads each run `ops_per_thread` short DB-bound ops
    (a fleet count) on their own Session. Past pool_size+max_overflow (30) callers must
    wait for a free connection; past pool_timeout they fail — this is the single
    process's DB envelope."""
    results = {}
    for c in concurrencies:
        latencies = []
        timeouts = 0
        errors = 0
        lock = threading.Lock()

        def worker():
            nonlocal timeouts, errors
            for _ in range(ops_per_thread):
                t = time.perf_counter()
                try:
                    db = SessionLocal()
                    try:
                        db.query(System).filter(System.status == "Active").count()
                    finally:
                        db.close()
                    dt = time.perf_counter() - t
                    with lock:
                        latencies.append(dt)
                except SAPoolTimeout:
                    with lock:
                        timeouts += 1
                except Exception:  # pylint: disable=broad-except
                    with lock:
                        errors += 1

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker) for _ in range(c)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        wall = time.perf_counter() - t0
        results[str(c)] = {
            "concurrency": c,
            "ops": c * ops_per_thread,
            "wall_s": round(wall, 3),
            "op_latency": _p(latencies),
            "pool_timeouts": timeouts,
            "errors": errors,
        }
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=500)
    ap.add_argument("--iterations", type=int, default=30)
    ap.add_argument("--reconcile-workers", type=int, default=8)
    ap.add_argument("--keep", action="store_true", help="skip cleanup (debug)")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    pool = engine.pool
    size = getattr(pool, "_pool", None) and pool.size() or 20
    overflow = getattr(pool, "_max_overflow", 10)
    out = {
        "hosts": args.hosts,
        "pool": {"size": size, "max_overflow": overflow, "ceiling": size + overflow},
    }
    print(f"[pra309] seeding {args.hosts} synthetic hosts (marked '{MARK}') ...")
    ids = seed(args.hosts)
    try:
        print(f"[pra309] seeded; {len(ids)} marked hosts present. measuring reads ...")
        out["reads"] = measure_reads(args.iterations)
        print("[pra309] measuring reconcile sweep ...")
        out["reconcile_sweep"] = measure_reconcile(ids, args.reconcile_workers)
        print("[pra309] measuring DB pool saturation ...")
        out["pool_saturation"] = measure_pool_saturation([1, 10, 20, 30, 45, 60])
    finally:
        if not args.keep:
            print("[pra309] cleaning up seeded rows ...")
            cleanup()

    print(json.dumps(out, indent=2))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"[pra309] wrote {args.json}")


if __name__ == "__main__":
    main()
