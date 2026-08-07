"""PRA-156: refresh ``distro_lifecycle`` from the seed JSON.

Run inside the backend container::

    docker compose exec backend python -m app.scripts.update_eol_data
    docker compose exec backend python -m app.scripts.update_eol_data --dry-run

Workflow:

  1. Operator edits ``backend/app/db/seed_data/distro_lifecycle.json``
     (the source of truth — the install-time Alembic migration also
     reads this file).
  2. Operator runs this script. It upserts every JSON entry into
     ``distro_lifecycle`` keyed by ``(distro_id, release, support_kind)``
     and prunes any DB row that no longer appears in the JSON, so the
     table converges on the JSON shape exactly.

No outbound network calls — airgap-compatible. The JSON is the only
source of truth; nothing scrapes endoflife.date at runtime.

The script honours ``DATABASE_URL`` from the environment (the same
env var the app uses); pass ``--dsn postgresql://...`` to override.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from sqlalchemy import create_engine, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..db.models import DistroLifecycle

# Resolve the seed JSON relative to the backend package so it works
# regardless of cwd. ``parents[2]`` walks scripts/ → app/ → backend/,
# then we descend into app/db/seed_data.
_SEED_PATH = (
    Path(__file__).resolve().parent.parent
    / "db"
    / "seed_data"
    / "distro_lifecycle.json"
)

_VALID_SUPPORT_KINDS = {"standard", "esm", "extended"}


def _load_seed() -> List[Dict[str, Any]]:
    with _SEED_PATH.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise SystemExit(f"{_SEED_PATH}: no 'entries' list")
    required = ("distro_id", "release", "eol_date", "support_kind", "source", "as_of")
    out: List[Dict[str, Any]] = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SystemExit(f"entry {idx}: not an object")
        missing = [k for k in required if k not in entry]
        if missing:
            raise SystemExit(f"entry {idx}: missing keys {','.join(missing)}")
        if entry["support_kind"] not in _VALID_SUPPORT_KINDS:
            raise SystemExit(
                f"entry {idx}: invalid support_kind={entry['support_kind']!r}"
            )
        # Parse date strings into date objects so SQLAlchemy doesn't
        # have to round-trip them through the driver as text.
        out.append(
            {
                "distro_id": entry["distro_id"],
                "release": entry["release"],
                "eol_date": date.fromisoformat(entry["eol_date"]),
                "support_kind": entry["support_kind"],
                "source": entry["source"],
                "as_of": date.fromisoformat(entry["as_of"]),
            }
        )
    return out


def _apply(session: Session, entries: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Upsert every entry and prune rows the JSON no longer carries.

    Returns ``(upserted, pruned)``.
    """
    keys_in_json = {(e["distro_id"], e["release"], e["support_kind"]) for e in entries}

    # ``updated_at`` is set explicitly: ``onupdate=datetime.utcnow`` on
    # the model only fires through the ORM, not through Core upserts
    # like this ``ON CONFLICT DO UPDATE``. Without setting it here,
    # refreshes would silently leave updated_at frozen at install time.
    now = datetime.utcnow()
    stmt = pg_insert(DistroLifecycle).values(entries)
    stmt = stmt.on_conflict_do_update(
        constraint="distro_lifecycle_unique_per_kind",
        set_={
            "eol_date": stmt.excluded.eol_date,
            "source": stmt.excluded.source,
            "as_of": stmt.excluded.as_of,
            "updated_at": now,
        },
    )
    session.execute(stmt)

    # Prune anything in the DB that isn't in the JSON anymore.
    pruned_count = 0
    for row in session.query(DistroLifecycle).all():
        key = (row.distro_id, row.release, row.support_kind)
        if key not in keys_in_json:
            session.execute(
                delete(DistroLifecycle).where(
                    DistroLifecycle.distro_id == row.distro_id,
                    DistroLifecycle.release == row.release,
                    DistroLifecycle.support_kind == row.support_kind,
                )
            )
            print(f"  pruned: {row.distro_id} {row.release} {row.support_kind}")
            pruned_count += 1

    return len(entries), pruned_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--dsn",
        default=os.environ.get("DATABASE_URL"),
        help="DB connection string. Defaults to $DATABASE_URL.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the JSON and report would-be changes without writing.",
    )
    args = parser.parse_args()

    if not args.dsn:
        print("error: no DSN — set DATABASE_URL or pass --dsn", file=sys.stderr)
        return 2

    entries = _load_seed()
    print(f"loaded {len(entries)} entries from {_SEED_PATH}")

    engine = create_engine(args.dsn)
    with Session(engine) as session:
        if args.dry_run:
            existing = {
                (r.distro_id, r.release, r.support_kind)
                for r in session.query(DistroLifecycle).all()
            }
            json_keys = {
                (e["distro_id"], e["release"], e["support_kind"]) for e in entries
            }
            would_insert = json_keys - existing
            would_prune = existing - json_keys
            for key in sorted(would_insert):
                print(f"  would insert: {key[0]} {key[1]} {key[2]}")
            for key in sorted(would_prune):
                print(f"  would prune:  {key[0]} {key[1]} {key[2]}")
            print(
                f"summary: {len(would_insert)} new, {len(would_prune)} pruned, "
                f"{len(json_keys & existing)} present"
            )
            print("dry-run: no changes written")
            return 0
        upserted, pruned = _apply(session, entries)
        session.commit()
        print(f"upserted {upserted} entries, pruned {pruned}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
