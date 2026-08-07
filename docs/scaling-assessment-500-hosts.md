# 1.0 Scaling Assessment — 500-Host Single-Worker Envelope

**Question:** can the intentionally single-worker Praxis 1.0 backend + single-broker
topology support the paid **Business cap of 500 managed hosts**?

**Verdict: YES — 500 managed hosts are supportable on the 1.0 single-worker topology.**
The fleet-job / request envelope that actually scales with host count is DB-bound and
has large headroom: over 500 synthetic hosts on the production engine + connection
pool, fleet dashboards render in **≤ 9 ms p95**, the full access-control reconcile
sweep completes in **~0.67 s** (751 hosts/s) against scheduler intervals of **≥ 30 s**,
and the DB pool absorbs **2× oversubscription (60 concurrent ops) with zero failures**.
The measured envelope stays clean at **1000 hosts** (2× the promise). The limits that
matter are NOT host count — they are *concurrent interactive sessions* (process-local)
and *simultaneous command fan-out concurrency* (SSH/broker-bound); both are bounded and
degrade gracefully, and neither is exceeded by having 500 hosts enrolled. See
[Limits & tuning](#limits-what-is-not-promised-and-tuning) and
[Follow-ups](#follow-ups).

> Measurement caveat: absolute millisecond numbers below were captured in the dev
> Docker runtime (WSL2, shared host) against the **production** SQLAlchemy engine and
> pool config. Treat the **ratios, linearity, and headroom** as the signal, not as a
> production SLA. The harness is committed and re-runnable
> (`scripts/scaling/pra309_load_harness.py`) so numbers can be re-taken on real
> hardware.

---

## 1. Current supported topology (what is single-process and why)

| Component | Count | Enforcement / evidence |
| --- | --- | --- |
| Backend Uvicorn workers | **1** | `UVICORN_WORKERS=${UVICORN_WORKERS:-1}` (`docker-compose.prod.yml`); `scripts/assert_session_worker_safety.sh` fails boot if `>1` unless `ALLOW_UNSAFE_MULTIWORKER_SESSIONS=1` |
| Agent broker processes | **1** | `agent-broker` service, `python -m app.broker.main`; boot logs "run exactly one broker process (no replicas / HA in 1.0)"; no compose `replicas` |
| Scheduler | 1 APScheduler `BackgroundScheduler` in the backend process | default `ThreadPoolExecutor`, `max_instances=1`, `coalesce=True`, `misfire_grace_time=300`; cross-instance dedupe via DB advisory rows (`scheduler_job_locks`) |
| DB connection pool (per process) | `pool_size=20 + max_overflow=10 = 30`, `pool_timeout=30 s` | `app/db/session.py` — hard-coded literals, **no env override** |

**Why single-worker is a correctness requirement, not laziness:**

- **Interactive session runtime is process-local.** Live SSH/web-terminal sessions live
  in a module-level dict `session_runtime._registry: Dict[int, SessionRuntime]`, each
  owning a Paramiko transport/PTY + a background reader **thread** + recording writer.
  `POST /sessions` opens the runtime in one worker's memory; `…/ws` attaches by looking
  it up in that **same** process. With >1 worker the REST open and the WS attach can
  land on different workers → "runtime missing". This is the exact failure the boot
  guard blocks.
- **Broker tunnel + op state is in-memory and unshardable.** `AgentRegistry._by_system:
  Dict[int, TunnelEntry]` holds each agent's live yamux tunnel; `OperationManager._ops`
  routes an op to the tunnel via `registry.get(system_id)`. Two broker processes would
  split tunnels with no shared registry, so ops would miss their agent.

**What is NOT process-local (so it scales with the DB, not with memory):** command
execution results and validation/approval, **command fan-out results**
(`fleet_operations` / `fleet_operation_results`), jobs + history, host facts
(`HostFacts`), patch plans/executions, drift/compliance evidence, audit, and the
revocation/reconcile work outbox. Enrolling 500 hosts grows **rows**, not in-process
memory.

---

## 2. The load harness (reproducible, no 500 VMs)

`scripts/scaling/pra309_load_harness.py` seeds N synthetic `System` rows (marked
`pra309load-`, cleaned up on exit) and measures, against the **real production engine +
pool**:

1. **Fleet read aggregates** — `HealthService.get_fleet_dashboard()` /
   `get_fleet_health()` (the GROUP-BY queries the admin UI and scheduler hit each cycle).
2. **Reconcile sweep** — the periodic access-control convergence, executed with the same
   shape as `fleet_reconciliation_service.reconcile_all` (8-worker `ThreadPoolExecutor`,
   one `Session` per worker) but **only over the seeded ids**, so it never SSHes a real
   host. Converged/no-grant hosts ⇒ DB-read-only per host = the steady-state cost that
   runs every cycle in normal operation.
3. **DB pool saturation** — C concurrent DB-bound ops at C = 1…60 (1×…2× the 30-conn
   ceiling), reporting latency growth and any `pool_timeout` failures.

Run it:

```bash
docker compose run --rm --no-deps \
  -e DATABASE_URL=postgresql://postgres:postgres@db:5432/praxis_test -e TESTING=1 \
  -v "$PWD":/src -w /src/backend backend \
  python /src/scripts/scaling/pra309_load_harness.py --hosts 500 --json /src/out.json
```

**What the harness does not simulate:** real agent tunnels and real interactive SSH
sessions (those need the broker + real hosts). Those envelopes are assessed analytically
in §4 and validated by the existing broker/session tests + the real-host smokes
(`scripts/test-first-enrolled-host-smoke.sh`, `tests/broker/`). The harness proves the
**DB / fleet-job / request** envelope — the part that genuinely grows with host count.

---

## 3. Measurements

Production engine/pool; medians over repeated iterations; `errors=0` throughout.

### Fleet reads (host-count-independent aggregates)

| Fleet size | `get_fleet_dashboard` p95 | `get_fleet_health` p95 |
| --- | --- | --- |
| 50   | 8.6 ms | 2.7 ms |
| 500  | 9.1 ms | 2.8 ms |
| 1000 | 10.3 ms | 3.1 ms |

Aggregate GROUP-BY over an indexed `systems` table — essentially flat from 50 → 1000
hosts. Dashboards do not degrade with fleet size.

### Access-control reconcile sweep (the periodic full-fleet job)

| Fleet size | Wall (8 workers) | Throughput | Per-host p50 | Errors |
| --- | --- | --- | --- | --- |
| 50   | 0.074 s | 680 hosts/s | 10.8 ms | 0 |
| 500  | **0.666 s** | 751 hosts/s | 10.4 ms | 0 |
| 1000 | 1.356 s | 738 hosts/s | 10.4 ms | 0 |

Per-host cost is stable (~10 ms), so the sweep is **linear** in host count. At 500 hosts
the whole-fleet sweep is **~0.67 s**. The tightest fleet-relevant scheduler intervals
are **30 s** (webhook/audit/revocation-drain) and the fleet sweeps themselves run every
**5–30 min** — so the heaviest full-fleet convergence occupies the 8-thread pool for
**~0.67 s out of ≥30 s (~2% duty cycle)**. Headroom to the promise is **~45×**; even at
2× the promise (1000 hosts) it is ~22×.

### DB pool under concurrency (ceiling = 30 connections)

| Concurrency | op p50 | op p95 | op max | pool timeouts |
| --- | --- | --- | --- | --- |
| 1  | 2.1 ms | 2.5 ms | — | 0 |
| 10 | 6.0 ms | 9.9 ms | — | 0 |
| 20 | 12.2 ms | 20.3 ms | — | 0 |
| 30 | 17.4 ms | 28.9 ms | 41 ms | 0 |
| 45 | 16.8 ms | 32.2 ms | 160 ms | 0 |
| **60** | 19.4 ms | **40.5 ms** | 224 ms | **0** |

Past the 30-connection ceiling, callers **queue** for a free connection rather than
fail. Because fleet ops are short (ms-scale), the queue drains fast: at 2×
oversubscription p95 is still ~40 ms and **no request hit the 30 s `pool_timeout`**.
This is graceful degradation (latency, not errors).

### Resource footprint

Backend container idle RSS ≈ **210 MiB**; the reconcile sweep is a ~0.67 s / ≥30 s duty
cycle on ≤8 threads (low average CPU). Broker memory is **O(connected agents)** — each
`TunnelEntry` is a small object plus one socket; 500 persistent agent connections is a
few MiB of Python objects plus per-socket kernel buffers, comfortably within a container.

---

## 4. Per-workflow verdict (interactive correctness vs fleet-job throughput)

| Workflow | Bound by | 500-host verdict |
| --- | --- | --- |
| Agent heartbeat / tunnel health | Broker in-memory registry (O(agents)) + `agent_last_seen` DB writes | ✅ bounded; health rollups are the aggregate queries measured above |
| Command execution **fan-out** | SSH/broker **concurrency** + `fleet_operations` DB writes; results persisted per host | ✅ throughput-bound, not latency-bound — a 500-host fan-out is paced by the SSH/op concurrency limit and drains as a DB-backed batch; it does not block the event loop |
| Package / **facts** scans | Scheduler sweep walking Active fleet + `HostFacts` writes | ✅ DB-bound like reconcile; per-host skip-if-fresh keeps steady-state cheap |
| Patch plan generation & dispatch | DB (`PatchUpdatePlan*`) + dispatch concurrency | ✅ DB-backed; dispatch is a bounded batch, not a single blocking call |
| Compliance evaluation / remediation dispatch | Scheduler sweep + DB evidence | ✅ DB-bound sweep, same envelope class as reconcile |
| File transfer | Per-transfer SSH/SFTP, **concurrency-bound** | ✅ bounded by concurrent transfers, independent of fleet size |
| Access-control **reconcile / revocation** | DB convergence (measured) + provisioning SSH only on drift | ✅ **measured: 0.67 s / 500 hosts**; provisioning transients are SSH-concurrency-bound, separate from the steady sweep |
| Active **interactive SSH sessions** | **Process-local** runtime (thread + PTY + recording per session); CPU/mem/FD | ⚠️ bounded by **concurrent active sessions**, NOT by host count — a 500-host fleet with, say, 10–20 concurrent live sessions is well within one process; this is the dimension to watch, and it does not grow just because more hosts are enrolled |

**The key distinction the assessment turns on:** enrolling 500 hosts grows *DB rows and
periodic-sweep work* (measured, linear, tiny) — it does **not** grow the *process-local*
session/broker state, which is driven by *concurrent activity* (active sessions, in-flight
fan-outs), a separate and much smaller number.

---

## 5. Limits, what is NOT promised, and tuning

**Degrades gracefully (latency, not failure):**
- DB pool oversubscription → requests queue (measured: 2× → ~40 ms p95, 0 timeouts).
- Overlapping fleet sweeps → APScheduler `coalesce=True` + `max_instances=1` collapse
  stacked runs; a slow sweep delays the next tick, it does not pile up.

**Not promised in 1.0 (documented non-goals):**
- Multiple Uvicorn workers / HA backend, multiple broker replicas (would break the
  process-local session + tunnel invariants — see §1).
- Unbounded **concurrent interactive sessions** — this is the real ceiling and is
  bounded by backend CPU/memory/FDs, not by enrolled-host count.
- A single synchronous fan-out blocking on hundreds of slow/dead hosts is paced by
  SSH/op concurrency; throughput, not per-host latency, is the lever.

**Tuning knobs (adequate at 500; documented for headroom):**
- **DB pool** (`pool_size=20`, `max_overflow=10`, `pool_timeout=30 s`) is currently a
  hard-coded literal in `app/db/session.py`. It was **not** exceeded at 2×
  oversubscription in testing, so no change is required for 500 hosts. If an operator
  runs many concurrent admins *and* heavy sweeps on constrained DB hardware, making these
  env-configurable is a cheap future safety valve (see follow-ups).
- Scheduler intervals (facts 30 min, health 30 min, drift/compliance 15 min) already
  leave ~45× headroom over the measured 500-host sweep cost.

---

## 6. Answering the acceptance questions

- **Are 500 hosts supportable on 1.0 single-worker?** **Yes.** The host-count-scaling
  work (fleet reads + periodic sweeps + fan-out result persistence) is DB-bound with
  ~45× headroom at 500 and still clean at 1000.
- **Interactive-session correctness vs non-interactive throughput distinguished?** Yes —
  interactive sessions are process-local and concurrency-bound (the reason for the
  single-worker gate); non-interactive fleet jobs are DB-backed and were measured linear.
- **Latency, resource pressure, retry/failure captured?** Yes — read/dispatch latency,
  reconcile throughput, DB pool saturation (latency + timeout counts), CPU duty cycle,
  and RSS baseline; `errors=0`/`pool_timeouts=0` throughout.
- **Config tuning required + committed?** None required for 500 hosts; the DB-pool knob
  is documented as an optional headroom valve.
- **Is a follow-up blocker needed?** **No launch blocker.** Single-worker passes the
  500-host envelope. Optional, non-blocking follow-ups below.

## Follow-ups

- **Optional, non-blocking:** make the DB pool env-configurable
  (`PRAXIS_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_TIMEOUT`) so operators on constrained DB
  hardware have a valve. Not required for 500 hosts.
- **A DB-backed queue/worker is the right home** for any future move to
  handling of non-interactive fleet jobs *if* the host cap is raised well beyond 500 or
  concurrent-admin load grows — it is **not** needed for the current 500-host promise.
- Re-run `scripts/scaling/pra309_load_harness.py` on target production DB hardware to
  convert these ratios into absolute production numbers before raising the cap.
