# Airgap export / import

End-to-end disconnected workflow. Praxis itself runs in airgapped
environments by exporting a signed content bundle on a connected
control plane, transporting the tar physically (USB, optical, NFS),
and importing it on the disconnected control plane as
`source_mode='imported_offline'` mirrors that don't sync upstream.

## At a glance

```
┌──────────────────┐                                ┌─────────────────────┐
│ Connected Praxis │                                │ Airgapped Praxis    │
│                  │   1. POST /airgap/signing-key  │                     │
│   ┌──────────┐   │                                │   ┌──────────────┐  │
│   │ Mirrors  │   │   2. Share bundle pubkey ◄─────┼───┤ Operator     │  │
│   │ Channels │   │      out-of-band                │   │ pins the key │  │
│   │ Profiles │   │                                 │   │ via          │  │
│   └────┬─────┘   │   3. POST /airgap/exports       │   │ POST         │  │
│        │         │      → tar on disk              │   │ /airgap/     │  │
│        ▼         │                                 │   │  import-trust│  │
│   ┌──────────┐   │   4. tar moves to airgap side ──┼──►│              │  │
│   │ Bundle   │   │      via USB / NFS / pigeon     │   │ POST         │  │
│   │ tar      │   │                                 │   │ /airgap/     │  │
│   └──────────┘   │                                 │   │   imports    │  │
│                  │                                 │   └──────┬───────┘  │
│                  │                                 │          ▼          │
│                  │                                 │   imported_offline  │
│                  │                                 │   mirrors + content │
│                  │                                 │   profiles          │
└──────────────────┘                                 └─────────────────────┘
```

A `bundle.tar` carries a self-describing descriptor (`bundle.json` +
`bundle.json.sig` at the tar root), every selected mirror's
`live/` tree + manifest sidecar, and the per-mirror signing
public-key material the importer needs to verify offline. Trust is
operator-pinned: the airgap side trusts only public keys it has
explicitly registered through `POST /airgap/import-trust`, never
keys carried inside the tar (they're decoration).

## Architecture lock

Every airgap feature answers "does this still work via
export/import?" That's why:

* `MirrorRepo` carries `source_mode ∈ upstream_sync | imported_offline`
  from the mirror engine — the importer flips imported mirrors to
  `imported_offline` and the scheduler skips them.
* `MirrorSyncRun.run_kind ∈ sync | sign_only | import` — imported
  rows are written as `run_kind='import' status='ok'` directly,
  never scheduler-owned.
* Channels and profiles travel in the descriptor as denormalized
  snapshots; the importer creates fresh rows with prefixed slugs
  (`imported-<bundle_short>-<original_slug>`) so subsequent re-imports
  don't collide.

## One-time setup

### Connected side: bootstrap the bundle signing key

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    https://praxis.connected.example/airgap/signing-key
```

Idempotent. First call generates a 4096-bit RSA key, stores the
private half in Vault at
`praxis/bundle-signing-key/<fingerprint>`, and persists the public
half on the `airgap_bundle_signing_keys` row. Returns
`{fingerprint, key_uid, status, created}`. Subsequent calls return
the existing active key with `created: false`.

### Pull the public key for transport

The airgap side needs this fingerprint pinned before it'll trust
any bundle. Easiest path is direct from the backend container:

```bash
docker compose exec backend python -c "
from app.db.session import SessionLocal
from app.db.models import AirgapBundleSigningKey
db = SessionLocal()
row = db.query(AirgapBundleSigningKey).filter_by(status='active').one()
print(row.armored_public_key)
" > exporter-pub.asc
```

Transport `exporter-pub.asc` to the airgap side (USB, secure email,
out-of-band whatever). Don't put it in the bundle tar — that's a
trust circular reference.

### Airgap side: pin the bundle public key

```bash
ARMORED=$(cat exporter-pub.asc)
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"armored_public_key\": $(jq -Rs . <<< "$ARMORED")}" \
    https://praxis.airgap.example/airgap/import-trust
```

Returns `{id, gpg_fingerprint, key_uid, added_at, deleted_at}`.
`deleted_at: null` on a fresh pin.

`POST /airgap/import-trust` is admin-only. The service derives the
fingerprint via `gpg --import` + `--list-keys` — operators don't
supply a fingerprint string, only the armored bytes. Active
fingerprint uniqueness is DB-enforced (partial unique index on
`WHERE deleted_at IS NULL`).

## Full export

Pick one or more profiles whose effective content you want to
ship. The planner derives channels and mirrors from each profile's
composition:

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"profile_slugs": ["prod-base"], "kind": "full"}' \
    https://praxis.connected.example/airgap/exports
```

Synchronous response (`descriptor_ready`):

```json
{
  "bundle_id": "11111111-2222-3333-4444-555555555555",
  "kind": "full",
  "status": "descriptor_ready",
  "bundle_descriptor_path": "/data/praxis/mirrors/.airgap-staging/.../bundle.json",
  ...
}
```

The tar assembly runs in the background. Poll for completion:

```bash
while true; do
    curl -sS -H "Authorization: Bearer $TOKEN" \
        https://praxis.connected.example/airgap/exports/$BUNDLE_ID \
        | jq -r .status
    sleep 5
done
# descriptor_ready → building → ok
```

Final state at `status: ok`:

```json
{
  "bundle_id": "...",
  "kind": "full",
  "status": "ok",
  "bundle_path": "/data/praxis/airgap-bundles/<bundle_id>.tar",
  "payload_sha256": "<64 hex>",
  "byte_count": 5234567890,
  ...
}
```

`bundle_path` is the file to transport. Operator copies it to a
USB drive (or whatever your transport is). On the airgap side,
mount the drive at a path under `PRAXIS_AIRGAP_IMPORT_STAGING`
(default `/data/praxis/airgap-import-staging`).

## Pinned snapshots and historical bytes (1.0 policy)

Praxis 1.0 stores mirror **bytes live-only** — there is no per-run historical
byte store. This is a deliberate, bounded policy, not a gap to work around:

- A mirror keeps exactly one materialized tree on disk (`<mirror>/live/`), the
  last-promoted sync. Older sync runs are retained as **metadata** —
  `mirror_sync_runs` rows plus their manifest/signature sidecars under
  `snapshots/` — governed by the mirror's retention (`keep_count` /
  `keep_within_days`). Retention **never** deletes `live/` or `work/` bytes.
- A channel's **pin** (`pinned_run_id`) is a **manifest / tracking pin, not a
  byte freeze.** It records "this content state," but the bytes it points at only
  still exist on disk if that run is still what's live.

So an airgap export with `--snapshot pinned` (or an explicit override) resolves
deterministically:

- **Pin is byte-equivalent to current live** (same `manifest_sha256` as the
  latest `ok` run) → the planner **canonicalizes to the latest-ok run** and
  exports the live bytes. The exported content is exactly the pinned state.
- **Pin differs from current live** → the export **fails closed** with
  `historical_bytes_unavailable` (a flat 422 whose `context` names the
  `mirror_slug`, `requested_run_id` / `requested_manifest_sha256`, and the
  `current_live_run_id` / `current_live_manifest_sha256`). Praxis refuses rather
  than silently exporting the *current* bytes under an old run id.

To resolve a `historical_bytes_unavailable` refusal: export `--snapshot latest`,
re-pin the channel to the current run, or re-sync/re-promote the desired content
so it becomes live again. If your environment truly needs exact reproduction of
arbitrary past states, keep the exported **bundle tars** (they are
self-contained and re-importable) as your historical archive — that is the
supported 1.0 mechanism for byte-exact history.

### Common export refusals

All return flat 422 bodies of shape `{code, message, context}`:

| `code` | What happened |
|---|---|
| `unknown_profile` | One of the requested `profile_slugs` doesn't exist or is soft-deleted. |
| `mixed_package_family` | Selected profiles span both `deb` and `rpm`. One bundle = one family. |
| `historical_bytes_unavailable` | Pinned/explicit run isn't byte-equivalent to current `live/`. The mirror engine doesn't keep historical bytes; either accept `--snapshot latest` or re-pin to the current run. |
| `mirror_signing_material_missing` | An in-scope mirror has no usable armored signing-key material declared. Run trust-bundle distribution before exporting. |
| `pin_unusable` | `--snapshot pinned` but the pinned `mirror_sync_runs` row is missing or non-ok. |
| `delta_parent_missing` / `delta_parent_not_ok` | (Delta only.) Parent bundle isn't on this instance or isn't `status='ok'`. |
| `delta_parent_scope_mismatch` | (Delta only.) Current scope adds mirrors not in parent. Re-export full. |

## Full import

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"/data/praxis/airgap-import-staging/<bundle_id>.tar\"}" \
    https://praxis.airgap.example/airgap/imports
```

Returns 202 with the row pre-created at `status='verifying'`:

```json
{
  "bundle_id": "...",
  "kind": "full",
  "status": "verifying",
  "path": "...",
  ...
}
```

Heavy verify + ingest runs in the background. Poll:

```bash
while true; do
    curl -sS -H "Authorization: Bearer $TOKEN" \
        https://praxis.airgap.example/airgap/imports/$BUNDLE_ID \
        | jq -r '.status, .error_text'
    sleep 5
done
# verifying → extracting → ok
```

On `status: ok` the response carries `target_mirror_slugs`: the
prefixed mirror slugs the importer created. Each becomes a
`MirrorRepo(source_mode='imported_offline', enabled=False)` plus
prefixed channels and profiles. Operator decides when to flip
`enabled=True` if they want hosts to consume the imported content.

Path safety: the tar must resolve under
`PRAXIS_AIRGAP_IMPORT_STAGING`. Symlinks are followed during
resolution; an escaping symlink is refused with
`tar_path_outside_staging`.

### Common import refusals

| Code | What happened |
|---|---|
| `bundle_descriptor_unreadable` | The tar is corrupt / non-tar / EIO. `context.reason ∈ tar_corrupt | tar_io_error`. |
| `bundle_signature_invalid` | No active trust pin matches the bundle's signature. Pin the right key, or check the operator copied the correct `exporter-pub.asc`. |
| `unsupported_bundle_version` | Bundle is from a future schema version this Praxis doesn't recognize. Upgrade the airgap side. |
| `bundle_already_imported` | Bundle ID already imported (`context.existing_status='ok'`). Pass `force: true` to retry a `failed` row, or wipe the row to reuse the slug for a re-import. |
| `bundle_already_imported` + `context.reason='import_in_progress'` | Another import for the same bundle is already running. Wait for it to finish. |
| `parent_bundle_missing` | (Delta only.) Parent bundle hasn't been imported here. Import it first. |
| `slug_collision` | Imported-prefixed slug collides with an existing mirror/channel/profile. The collision context lists every conflict. |
| `payload_integrity_failure` | A payload member's bytes don't match the signed sha256. Bundle was tampered or corrupted in transit. |
| `manifest_signature_invalid` | Per-mirror manifest signature can't be verified against any key declared in the descriptor. |

## Delta export / import

Delta bundles ship only files that differ from a parent bundle the
connected side previously built (parent's `airgap_bundles.bundle_id`).
Tar carries the diff + a fresh manifest sidecar; the importer
walks the airgap side's `airgap_imports` parent chain, copies each
parent layer's `live/`, then overlays the delta's files. After
assembly the importer recomputes the assembled tree's manifest
sha and verifies it matches the descriptor's declared sha
(post-assembly cross-check).

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "profile_slugs": ["prod-base"],
        "kind": "delta",
        "parent_bundle_id": "<full-bundle_id>"
    }' \
    https://praxis.connected.example/airgap/exports
```

The airgap side must already have the parent bundle imported at
`status='ok'`:

```bash
# Import the parent first.
curl -sS -X POST ... -d '{"path": "/.../parent.tar"}' \
    https://praxis.airgap.example/airgap/imports
# Wait for status=ok, then import the delta.
curl -sS -X POST ... -d '{"path": "/.../delta.tar"}' \
    https://praxis.airgap.example/airgap/imports
```

### Delta limitations (v1)

* **No deletions.** A file present in the parent but absent from
  the current export is refused at export time
  (`DeltaDeletionsUnsupported`). v1.1 will add a `removed_paths`
  schema field; for now, restore the file or re-export full.
* **Cross-instance parents not supported.** The connected side
  builds deltas only against parents it itself built (so the
  parent's `bundle_descriptor_path` is on disk). To delta against
  a parent built on a different connected instance, re-export full.
* **Single linear chain.** No multi-parent merges.
* **Scope can narrow but not widen.** A delta can drop profiles
  the parent had, but adding a profile or a new mirror to an
  existing profile refuses with `delta_parent_scope_mismatch` or
  `all_mirrors_dropped`.

## Standalone CLI inspection

Run inside the backend container against any tar on disk. Neither
subcommand consults the database or modifies state:

```bash
# Pretty-print the descriptor JSON without verifying anything.
docker compose exec backend python -m app.cli.airgap inspect /tmp/bundle.tar

# Verify bundle.json.sig against an operator-supplied public key.
# Useful as a pre-pin sanity check.
docker compose exec backend python -m app.cli.airgap verify \
    /tmp/bundle.tar --key-file /tmp/exporter-pub.asc
```

Exit codes: 0 success, 2 verify failed, 3 bad arguments (including
argparse failures: missing/unknown subcommand, missing `--key-file`,
unknown options), 4 IO error (corrupt tar, descriptor body
unreadable), 5 unsupported bundle version (newer Praxis required).

The `praxis-airgap` binary is wired as a `console_scripts` entry
point in `backend/setup.py`, so once the backend image is built it's
also reachable directly:

```bash
docker compose exec backend praxis-airgap inspect /tmp/bundle.tar
```

Both invocations are equivalent; `python -m app.cli.airgap …` keeps
working as a fallback.

## Key rotation

The bundle signing key isn't rotated automatically, but rotation is a
first-class, operator-safe workflow — **no manual database edits.** Use the
**Content → Airgap Keys** page, or the API directly. Rotation is an *immediate*
model: the current active key is demoted to `rotating_out` (still valid for
verifying bundles you already exported) and a fresh `active` key is generated in
one step. Exactly one key is ever `active`.

1. **(Connected side) Rotate.** `POST /airgap/signing-keys/rotate` (admin), or
   the **Rotate** button on the Airgap Keys page. The response returns the
   demoted `old` key and the new `active` key with its armored public key. List
   all keys any time with `GET /airgap/signing-keys` (active, rotating-out, and
   retired, each with its armored public key for distribution). The rotation is
   audited as `airgap.signing_key.rotated` (old/new fingerprints; no key
   material).

2. **Pin the new public key on the airgap side *before* importing new bundles.**
   Bundles exported *after* the rotation are signed by the **new** key, so the
   import-side instance must trust it first: distribute the new armored public
   key out-of-band and pin it with `POST /airgap/import-trust` (or the Import
   Trust Pins section of the page). Keep the **old** pin in place too — the
   importer accepts a bundle if any active pin verifies it, so both old and new
   bundles import cleanly during the overlap.

3. **Remove the old pin once you no longer import old bundles.** Soft-delete the
   old pin via `DELETE /airgap/import-trust/{key_id}` (audited as
   `airgap.import_trust.removed`). Soft-deleted pins are retained for audit.

4. **(Connected side) Retire the old signing key** once no consumer needs to
   verify bundles it signed: `POST /airgap/signing-keys/{key_id}/retire`
   (admin), or the **Retire** button next to a `rotating_out` key. Retiring the
   `active` key is refused — rotate first. Retirement is audited as
   `airgap.signing_key.retired`.

Private key material and Vault paths never appear in any of these API responses
or audit events; only fingerprints, key UIDs, statuses, and armored **public**
keys are exposed.

## Troubleshooting

### `bundle_descriptor_unreadable` / `tar_corrupt`

The tar didn't survive transport. Re-copy. If the issue
reproduces, run `tar -tvf <bundle.tar>` to see where parsing
fails.

### `payload_integrity_failure` on `Release`

A network filesystem corrupted bytes in transit. Re-export and
move via a different transport (or `sha256sum` the tar at both
ends).

### `slug_collision` on every retry

A previous import landed the prefixed slugs and they're still
present (possibly soft-deleted, which still collides per the
unique-slug constraint). Either soft-delete-then-physically-remove the
existing rows in a follow-up cleanup, or re-export with a
different `bundle_id` (Praxis assigns these as UUIDs — re-running
the export on the connected side produces a fresh ID). v1
intentionally does not auto-undelete imported entities to avoid
accidental data churn.

### Force-reuse of a `failed` import row

Pass `force: true`:

```bash
curl -sS -X POST ... -d '{"path": "/.../bundle.tar", "force": true}' \
    https://praxis.airgap.example/airgap/imports
```

Refusals on force:

| `context.reason` | Meaning |
|---|---|
| `force_refused_on_completed_import` | Existing row is already `status='ok'`; v1 doesn't cascade-replace imported entities. Soft-delete then re-import, or wait for the v1.1 cascade-replace path. |
| `force_reuse_kind_mismatch` | Existing row is `kind='full'` but the new tar is `kind='delta'` (or vice versa). Force-reuse must point at the same lineage. Wipe the row to start fresh. |
| `force_reuse_parent_bundle_id_mismatch` | Same idea for delta lineage. |

### `delta_parent_scope_mismatch` after a recent profile edit

Someone added a channel or mirror to a profile after the parent
was exported. The mirror has no parent baseline to diff against.
Either re-export full, or undo the channel/mirror addition
before re-running the delta.

### Cold-rebuild gate green but real-gpg test skipped

Hosted CI doesn't have the backend Docker image, so
`tests/services/test_pra160_real_gpg_integration.py` skips with
`gpg binary not available`. Cold-rebuild inside the backend image
sets `PRAXIS_REQUIRE_AIRGAP_TOOL_TESTS=1` so a future Dockerfile
that drops `gnupg` fails loudly at module import. Don't add a
unit test that fakes `mirror_gpg.verify_detached` and call it
"real-gpg" — the real-gpg test deliberately uses the real binary
so drift between unit-test fakes and the real verifier surfaces
in CI.

## Reference

* `app/services/airgap/planner.py` — export-side scope + diff
  validation.
* `app/services/airgap/orchestrator.py` — export build + idempotent
  re-verification on `ok` rows.
* `app/services/airgap/tar_assembler.py` — tar layout, deterministic
  metadata, payload-index integrity check on write.
* `app/services/airgap/importer.py` — import verify chain, parent
  chain walk, post-assembly manifest sha verification.
* `app/services/airgap/import_trust_service.py` — operator-pinned
  bundle public keys.
* `app/services/airgap/schema.py` — `BundleDescriptor` + canonical
  bytes serialization.
* `app/cli/airgap.py` — read-only inspection / verify CLI.

End-to-end test: `tests/services/test_pra160_real_gpg_integration.py`
exercises the full export → transport → pin → import flow with
real `gpg` signatures inside the cold-rebuild gate.
