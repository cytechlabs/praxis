---
title: Access revocation
description: How quickly each kind of access stops working after it is revoked, and what to do when you need it gone now.
---

Praxis 1.0 routes every access-removal trigger through one common revocation
orchestration path (`app/services/revocation_service.py`). This document
states, honestly, what that path guarantees and what residual exposure remains.

## Triggers that flow through the common path

- ordinary binding **delete / disable / role-narrowing update**;
- **JIT** access-request **revoke** and **expiry**;
- **application-role removal** and **user deactivation** (`identity_access_service`);
- **access-review item revoke**;
- **emergency / session lock**.

All of these narrow materialized access through the atomic grant recompute
(`access_binding_service.recompute_grants`). Recompute is the single choke
point: it computes the set of `(user, system, login)` scopes that lost **active**
(expiry-aware) access and, in the **same transaction** as the grant change
(outbox), enqueues one `revocation_work` row per scope. If the narrowed grants
commit, the matching cleanup work exists, so a process restart never drops it.

## What is guaranteed, and when

| Effect | Timing |
|---|---|
| **New authorization denied** | **Synchronous**, in the revoking request/transaction. This is the hard security boundary: grant state is the authority, and the decision denies expired/absent grants. A failed session-close or host reconcile **never rolls access back on**. |
| **Reachable in-process session closed** | Best-effort **immediately**, before/with the response, via `session_service.close_session` + the runtime registry. Valid under the supported **single-worker** topology (`UVICORN_WORKERS=1` with interactive SSH). If the backend scales out, this becomes dispatched termination (see *Assumptions*). |
| **DB-only / cross-worker session closed** | By the **guarded scheduler drain** (`revocation_drain`, every 30 s, one worker per tick) within one scheduler interval. The drain re-derives desired state, so a session under **restored** access is left alone. |
| **Reachable host cleanup** (stale principals, stale sudoers drop-ins, Praxis-owned accounts) | **Queued immediately**, applied by the drain via `fleet_reconciliation_service.reconcile_system`, and **retried with bounded backoff** until success or operator-visible failure. |
| **Offline / unreachable host** | **Visibly pending/error/noncompliant** with `last_error`, `attempt_count`, `next_retry_at`; retried on reconnect. **No claim of synchronous host cleanup.** |

The drain item is a **signal to reconverge** a scope, not a stored "remove login X"
imperative: `reconcile_system` re-derives the current desired state at execution
time. Access restored before the drain runs is therefore preserved.

Operators watch progress at **`GET /fleet/revocations`** (tenant-wide admin):
pending/error/completed counts plus per-host `system_id` / `last_error` /
`attempt_count` / `next_retry_at` for everything still unreconciled.

## Cert enforcement and the residual (stated precisely)

Praxis authenticates interactive SSH with short-lived Vault-signed **user
certificates**. On each managed host, sshd is configured
(`AuthorizedPrincipalsCommand`) to accept a cert only if its principal is listed in
`/etc/praxis/principals.d/<login>`. Reconciliation rewrites that file from the
current active grants (`host_user_provisioning_service._principals_for`, which omits
expired/removed grants), so **once host cleanup lands on a reachable host the revoked
identity's principal is removed and its cert is rejected there**, enforced through
the AuthorizedPrincipals path, not merely local-account removal.

The honest residual: **a revoked identity holding an unexpired cert who connects
directly to an unreconciled or offline host, bypassing Praxis, may retain access
until the cert's Vault max TTL.** That ceiling is **1 hour or less** (Vault role
`ssh-client-signer/roles/praxis-user` `max_ttl = 1h`; default
`FleetRole.max_session_s = 3600`). Praxis 1.0 makes **no offline cert-revocation
guarantee**: there is no CRL or OCSP responder to consult.

- **Urgent containment** for that residual is **CA rotation / fleet-wide identity
  reset** (invalidates all outstanding certs at once), deliberately distinct from
  normal per-identity revocation.

## Assumptions and boundaries

- **Single-worker topology.** Immediate in-process session close assumes the
  supported `UVICORN_WORKERS=1` interactive-session model. Under multiple workers, a
  live channel in another worker is closed at the DB level immediately and by the
  drain within one interval; the live channel there terminates on its own sweep/EOF.
  A future multi-worker model would dispatch termination to the owning worker.
- **Ownership.** Praxis modifies or deletes a host account only when it can
  prove it owns it via a **root-owned marker** (`/etc/praxis/managed-users/<login>.json`)
  written when Praxis creates the account. A pre-existing Linux account with the same
  username is **never** implicitly adopted: provisioning refuses to touch it (no
  `usermod`, no group/principal replacement) and removal refuses to delete the
  account/home. The `HostUserState` ledger row alone does **not** prove ownership.
  Marker tampering/absence, wrong owner, unsafe perms, or a login mismatch fail
  closed to `HostUserState.state = "error"` so revocation retry/status surfaces the
  host. Archive, `userdel`, and marker-verification failures are real errors (no
  silent `|| true`). Praxis-namespaced artifacts (the principals file and any
  `praxis-<login>` sudoers drop-in) are always safe to remove; that is cleanup, not
  adoption.
  - **Upgrade residual:** hosts provisioned before the ownership marker existed
    have no marker. Reconcile fails those accounts closed (visible `error`) rather
    than adopting them by username; markers are **not** backfilled onto arbitrary
    existing accounts. Re-provisioning through a future explicit, audited adoption
    workflow is required to bring pre-marker accounts back under management.
- **Privilege-baseline** sudoers-drop-in cleanup drains through this same
  scheduled reconcile path (`reconcile_pending_privilege`), not a bespoke sweep, and
  therefore stays pending/`error` for any account whose ownership cannot be verified.
