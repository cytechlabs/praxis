---
title: Distribution lifecycle data
description: Where end-of-life dates come from, how they are refreshed, and how Praxis uses them.
---

Praxis ships a static end-of-life reference dataset for the
distributions it supports. The data drives the per-host lifecycle
status (`supported` / `approaching-eol` / `unsupported` / `unknown`)
shown on host detail, the fleet dashboard widget, the smart-group
`lifecycle.*` predicates, and the EOL approaching/reached
notifications.

## Source of truth

The seed JSON at
`backend/app/db/seed_data/distro_lifecycle.json` is the single source
of truth. Two consumers read it:

1. The Alembic migration `pra156_distro_lifecycle` bulk-inserts the
   JSON contents at install time.
2. `app.scripts.update_eol_data` upserts the JSON contents into a
   running install, which is the operator-facing refresh path. Invoked via
   `docker compose exec backend python -m app.scripts.update_eol_data`.

There is **no runtime fetch** from `endoflife.date` or any other
upstream service. Praxis does not call out to the internet for EOL
data, which keeps the lifecycle layer airgap-compatible.

## Schema

Each entry:

```json
{
  "distro_id":    "ubuntu",
  "release":      "22.04",
  "eol_date":     "2027-06-01",
  "support_kind": "standard",
  "source":       "endoflife.date",
  "as_of":        "2026-07-16"
}
```

| field          | meaning                                                           |
| -------------- | ----------------------------------------------------------------- |
| `distro_id`    | Host-reported id, matches `host_facts.distro_id_facts`            |
| `release`      | Host-reported release, matches `host_facts.distro_release`        |
| `eol_date`     | ISO date when this support window ends                            |
| `support_kind` | `standard` / `esm` / `extended` (multiple kinds may coexist)      |
| `source`       | Where the date was last verified from                             |
| `as_of`        | ISO date when the entry was last verified                         |

`(distro_id, release, support_kind)` is unique. A release may have
both a `standard` row and an `esm` (or `extended`) row. Ubuntu LTS
releases are the most common example.

The `LifecycleService.compute` path consumes
**`support_kind='standard'` rows only**. ESM and extended rows are
seeded in advance for the override behavior
(`distro_lifecycle_override`), which lets a smart group mark its hosts
as eligible for an extended support window.

## Refreshing the data

When a vendor publishes a new release or extends a support window:

1. Edit `backend/app/db/seed_data/distro_lifecycle.json`.
2. Bump the `_meta.as_of` to today (and the per-row `as_of` for the
   rows you touched).
3. Validate the JSON and preview the diff against the live DB
   without writing:

   ```sh
   docker compose exec backend python -m app.scripts.update_eol_data --dry-run
   ```

4. Apply the change:

   ```sh
   docker compose exec backend python -m app.scripts.update_eol_data
   ```

The script upserts every entry by `(distro_id, release, support_kind)`
and prunes any DB row that no longer appears in the JSON. After the
script runs, the `distro_lifecycle` table matches the JSON exactly.

The `as_of 2026-07-16` snapshot covers the current 1.0-era releases:
Ubuntu 22.04/24.04/26.04 (+ older ESM rows), Debian 12/13 (+ older),
RHEL/Rocky/AlmaLinux 8/9/10, matching the
[Support Matrix](support-matrix.md).

## Fleet summary and unknown reasons

`GET /lifecycle/summary` returns the fleet bucket `counts`
(`supported` / `approaching_eol` / `unsupported` / `unknown`) plus an
`unknown_reasons` breakdown that partitions the unknown bucket so the
fleet dashboard's Unknown tile is actionable rather than opaque:

| reason                 | meaning                                                        | operator action                                             |
| ---------------------- | -------------------------------------------------------------- | ----------------------------------------------------------- |
| `freshness`            | Facts are stale (older than the staleness threshold) or the host has never reported facts | Refresh host facts / check enrollment and connectivity      |
| `missing_distro_facts` | A facts row exists but reported no `distro_id` / `release`     | Re-collect facts; investigate a host whose `os-release` is unreadable |
| `no_lifecycle_row`     | The host's `(distro_id, release)` has no matching seed row     | Add the pair to the seed (below) and re-run the refresh     |
| `other`                | Defensive bucket for any unknown verdict without a recognized reason (normally 0) | none |

`sum(unknown_reasons.values()) == counts.unknown` by construction. The
same three reasons appear on host detail's Lifecycle row for a single
host; the summary aggregates them fleet-wide.

## RHEL-family release matching

Hosts in the RHEL family (`rhel`, `rocky`, `almalinux`) report
`/etc/os-release` `VERSION_ID` with the minor included, for example
`8.10`, `9.4`, `9.5`. The collectors persist that string verbatim,
so `host_facts.distro_release` carries the minor.

The lifecycle lookup normalizes this: it tries the exact release
first, then for RHEL-family distros falls back to the major-only
release. So a seed entry of `(rhel, 9, standard)` covers every
`9.x` host. Operators only need per-minor entries when a specific
minor has a different EOL date, seed `(rhel, 9.4, standard)` to
record that, and exact-match precedence will pick it up over the
major row.

Ubuntu's LTS designators (`22.04`, `24.04`) are NOT major.minor
and the fallback never strips them. Debian releases are major-only
in the wild, so no normalization is needed there either.

## What NOT to put in the seed

- Per-customer support entitlements (use `distro_lifecycle_override`
  instead).
- Distros Praxis doesn't actually manage. Empty `(distro_id, release)`
  pairs in the table generate `unknown` verdicts for any host that
  matches them; missing pairs do the same. There's no benefit to
  pre-seeding distros you don't have hosts for.
- Build / kernel-specific dates. The lifecycle layer is keyed by
  release, not by kernel.

## Discovering new `(distro_id, release)` pairs

If a host shows `lifecycle.status == "unknown"` because no row matches
its `distro_id_facts` / `distro_release` strings, the host detail's
Lifecycle row will surface the unknown-reason
(`no_lifecycle_row`). Add the corresponding entry to the seed and
re-run the script.
