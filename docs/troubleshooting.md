---
title: Troubleshooting
description: Diagnose the failures operators actually hit, from a stack that will not start to a host that will not patch.
---

Work from the symptom you can see. Each section ends with what to gather if it
is still broken; take that to [support](support.md).

## The stack will not start

**Check what is actually failing:**

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy ps

docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    logs backend
```

| Symptom | Cause |
|---|---|
| Backend exits immediately, complaining about configuration | A production startup check failed. The log names the variable. `SECRET_KEY` and `POSTGRES_PASSWORD` have no safe default and weak values are refused. |
| Backend refuses to start over worker count | `UVICORN_WORKERS` is above 1. One worker is the supported model while interactive sessions are process-local. |
| Database container refuses the retired default password | `POSTGRES_PASSWORD` is still `postgres`. Choose a real value. |
| Compose reports an unknown tag or ignores overrides | Compose is older than v2.24 and does not understand `!override`. Upgrade Compose. |

## The site is unreachable in a browser

Almost always the proxy profile.

The backend and frontend publish **no host ports** by design. Caddy is the only
ingress. If you started the stack without `--profile proxy` and you are not
fronting it with your own proxy, nothing is listening for a browser and that is
intentional.

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

Otherwise:

- **Certificate warnings** in `internal` TLS mode are expected until you trust
  Caddy's local root. For a real deployment use `acme` or `byo`.
- **ACME fails to issue.** `PRAXIS_DOMAIN` must resolve publicly and port 443
  must be reachable from the internet.
- **Redirects land on the wrong host.** `PUBLIC_BASE_URL` does not match the URL
  users actually use.

## Nothing can reach any host

If every host went unreachable at once, suspect the secrets service before the
network.

Open **Secure > Vault Management**. A status of sealed, no token, or
connection error means no credential can be read, so every new connection fails
while existing pooled sessions keep working until they time out. This presents
as SSH errors, which sends people to the wrong place.

Unseal or restore the token; the state clears on the next health check. See
[production hardening](production-hardening.md).

## One host is unreachable

A host flips to Unreachable after consecutive health check failures, tuneable
under **Settings > Connection Settings**.

Work through it in this order:

1. **Name resolution and routing** from the control plane, not from your laptop.
2. **The credential.** Rotating a secret out of band under a linked credential
   will do this. Test the credential from its detail page.
3. **Host key changes.** A changed host key blocks connections under a `strict`
   or `tofu` policy. Review it under **Secure > SSH Security** and approve
   it if the change was legitimate, such as a rebuild. Do not approve one you
   cannot explain.
4. **Certificate trust.** If certificate trust was deployed and the signing CA
   has since been rotated, the host needs trust redeployed. Password
   authentication keeps working meanwhile.

## A host registers but never inventories

Usually escalation rather than connectivity. Package scanning needs to run, and
package changes need privilege.

Check the credential's escalation method. `nopasswd` requires a matching
`NOPASSWD:` entry on the host for the commands Praxis runs. Confirm by running
one command through **Operate > Run Command** and reading the error
rather than guessing.

## A patch or reboot will not dispatch

| Row condition | Meaning |
|---|---|
| `missing_sudo_method` | The credential does not declare how to escalate. Set one and re-dispatch. |
| `unknown_sudo_method` | The escalation method is not recognised. Same fix. |
| `window_missing`, `window_disabled`, `window_unusable` | A reboot could not be scheduled. It stays **pending** rather than failing. Fix the maintenance window and re-run scheduling; pending reboots dispatch on the next pass without rebuilding the plan. |
| `reboot_evidence_unknown` | The host could not say whether it needs a reboot, so the row stays **pending** instead of reading as "not required". On an RPM host the usual cause is `needs-restarting` not being installed; otherwise the probe timed out, the transport failed, or the output was unusable. Fix that, then re-run the reboot reconcile for the execution. |

Dispatch refusing is deliberate. It is better than running unprivileged and
failing opaquely partway through a fleet.

A pending row also holds back dependent waves. That is the point: a wave that
cannot prove the previous one finished rebooting must not start.

## The reboot queue says it is incomplete

The plan or execution detail page shows a *Reboot queue incomplete* warning,
and `summary.reconciliation.action_required` is true. The counts beside it are
not a complete account of which hosts still need a reboot, so do not read them
as "nothing outstanding".

- `status: incomplete` means hosts finished patching without a queue row.
- `status: failed` means a reconcile pass itself failed; `last_failure` carries
  the reason.

Re-run the reboot reconcile for that execution. A successful pass rebuilds the
queue and clears the marker. Until it does, dependent waves stay blocked with
the gate reason `reboot_reconcile_failed`.

## The dashboard will not show a security count

It shows `Not scanned`, `Scanning`, `Scan failed`, or `Partial scan` instead of
a number. That is the intended behavior: a count, zero included, is only shown
once every host in scope has a completed security scan behind it.

| State | What to do |
|---|---|
| `Not scanned` | Run a security scan. An ordinary package scan does not classify security updates, so it never moves this state. |
| `Scanning` | Wait. A scan still marked running after 30 minutes stops counting as in flight on its own. |
| `Scan failed` | Read the failure reason shown with it, fix the host, and rescan. |
| `Partial scan` | Some hosts in scope are not covered, or a scan could not use part of its result. Any number shown is a floor (`N+`), not a total. Rescan the uncovered hosts. |

See [security updates](packages.md#security-updates) for how the states are derived.

## A host will not patch, and it is not an error

Check the [Linux support matrix](support-matrix.md). Inventory is broader than
servicing: `zypper`, `pacman`, and `apk` hosts appear in inventory but are not
serviced for package changes. That is a boundary, not a bug.

Also check whether the package is **held** on that host. Held packages are
skipped by update jobs and still appear in inventory.

## The agent will not come online

1. `sudo systemctl status praxis-agent` on the host, and its journal.
2. The agent dials **out** to the broker on 8443. Confirm the host can reach it,
   and that the broker is published.
3. Confirm the certificate and key are in place under `/etc/praxis-agent/` and
   that `config.json` names the right system ID.
4. From the control plane, the host should report `agent_status: active` and
   `agent_liveness: online`.

If enrollment itself failed, re-run it. Sending `host_fingerprint` makes
redemption idempotent, so a retry does not consume another use of the
activation token.

## The terminal will not open on an agent host

Working as designed. **Interactive sessions always use SSH**, on every host
including agent-enrolled ones. The host needs SSH reachability and deployed
certificate trust. Setting a host's transport preference to `agent` does not
move the terminal onto the agent. See [transports](transports.md).

## A command is rejected

Two different gates, with different fixes:

- **A validation rule** rejected it before whitelist matching. These are hard
  bans on dangerous patterns. Check **Operate > Validation Rules** for the
  reason.
- **No whitelist entry matched.** Add an entry, or use an existing one. Commands
  that are rejected frequently are a signal the whitelist needs an entry, and
  **Operate > Command Metrics** shows which.

If it is waiting instead of rejected, it matched an entry that requires
approval. Multi-level entries need several distinct approvers, and a single
rejection short-circuits the whole request. Requests expire, and an expired
request must be resubmitted.

## A mirror will not serve

A mirror that shows as synced but reports a signing or upstream trust error is
**not safe to serve**, and Praxis will not pretend otherwise.

- **Unverified or expired upstream key**: the sync fails closed. Repair the
  trust.
- **Signing key not provisioned**: the mirror can pull but cannot sign, so hosts
  will not trust it.
- **Family mismatch**: a channel can only bundle mirrors of the same `deb` or
  `rpm` family.

## A host will not apply a content profile

A host subscribed to two profiles, directly and through a group, resolves to a
conflict and refuses to apply rather than guessing. Remove the ambiguity so it
resolves to a single effective profile. See
[mirrors and content](mirrors-and-airgap.md).

## An airgap bundle will not import

The offline side trusts a bundle only if a pinned public key verifies its
signature, never the key bytes carried inside the bundle. After the exporter
rotates its signing key, pin the new public key on the importing side before
importing anything signed with it. Keep the old pin during the overlap; the
importer accepts a bundle if any active pin verifies it.

An export with **pinned** snapshot selection can be refused with
`historical_bytes_unavailable`. Mirror bytes are live-only, so a pin to a run
that is no longer live cannot be reproduced byte-exact. Export **latest**,
re-pin to the current run, or use the earlier bundle as the archive.

## Alerts are not arriving

Every dispatch records an attempt with status, response code, and next retry.
Failures retry on a backoff and dead-letter after five attempts; dead-lettered
rows show a retry control.

Check delivery history on the alert configuration before suspecting the
destination. Use **Test** to fire a synthetic payload and confirm the URL and
signing secret. If the configuration is scoped to a smart group, only events
from members of that group dispatch at all.

## Paid features are locked

A paid action without the entitlement returns HTTP 402 and shows as locked.
Check **Settings > License** for the current edition, and
[rotate a licence](guide-license-rotation.md) if a key was rejected.

## What to gather before asking for help

- The Praxis version and how you deployed it.
- The exact error, copied rather than described.
- `docker compose ... ps` and the relevant service log.
- For a host problem: its transport, its credential's escalation method, and
  whether other hosts with the same credential work.
- For an agent problem: `praxis-agent version --json`, which carries the full
  commit SHA.

Then see [support](support.md).
