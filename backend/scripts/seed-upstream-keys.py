#!/usr/bin/env python3
"""Airgap-friendly seed script for mirror_upstream_keys (PRA-158 #4c).

Reads ``app/db/seed_data/upstream_keys.json`` (or a path passed via
``--seed``) and imports each entry as a Praxis-wide upstream trust
anchor via ``MirrorUpstreamKeyService.create_from_armored``.

Idempotent: if a fingerprint is already in the table, the script
logs a "skip" line and moves on. Empty seed files are a clean
no-op.

NEVER fetches anything from the network — operators populate the
seed file from authoritative sources of their choice (distro docs,
existing trusted hosts, PRA-160 import bundles).

Usage:

  docker compose exec backend python /app/scripts/seed-upstream-keys.py
  docker compose exec backend python /app/scripts/seed-upstream-keys.py \\
      --seed /custom/path/upstream_keys.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("seed-upstream-keys")

DEFAULT_SEED_PATH = Path("/app/app/db/seed_data/upstream_keys.json")


@dataclass(frozen=True)
class SeedSummary:
    imported: int
    skipped_duplicate: int
    failed: List[str]  # human-readable error lines


def _load_entries(seed_path: Path) -> List[dict]:
    if not seed_path.is_file():
        raise FileNotFoundError(f"seed file not found: {seed_path}")
    raw = json.loads(seed_path.read_text())
    entries = raw.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError(f"{seed_path}: 'entries' must be a list")
    return entries


def import_seed(seed_path: Path, db_session) -> SeedSummary:  # noqa: ANN001
    """Import every entry in ``seed_path`` into ``mirror_upstream_keys``.

    Returns a summary. Caller is responsible for opening + closing
    the DB session (the script's main wraps a fresh ``SessionLocal``).
    """
    from sqlalchemy.exc import IntegrityError

    from app.services.mirror_upstream_key_service import (
        MirrorUpstreamKeyError,
        MirrorUpstreamKeyService,
    )

    entries = _load_entries(seed_path)
    if not entries:
        logger.info("seed file %s has no entries — nothing to import", seed_path)
        return SeedSummary(imported=0, skipped_duplicate=0, failed=[])

    service = MirrorUpstreamKeyService(db_session)
    imported = 0
    skipped = 0
    failed: List[str] = []

    for idx, entry in enumerate(entries):
        name = (entry.get("name") or "").strip()
        armored = entry.get("armored_public_key")
        notes = entry.get("notes")
        if not name or not armored:
            failed.append(
                f"entries[{idx}]: missing required field 'name' or "
                "'armored_public_key'"
            )
            continue

        try:
            row = service.create_from_armored(
                name=name, armored_public_key=armored, notes=notes
            )
        except IntegrityError:
            # Duplicate fingerprint — already imported. Log + continue.
            db_session.rollback()
            existing = service.get_by_fingerprint(
                _peek_fingerprint(armored, name)
            ) or _NameTag(name=name, gpg_fingerprint="<unknown>")
            logger.info(
                "skip %r: fingerprint %s already imported",
                name,
                existing.gpg_fingerprint,
            )
            skipped += 1
            continue
        except MirrorUpstreamKeyError as exc:
            failed.append(f"entries[{idx}] ({name!r}): {exc}")
            continue

        logger.info("imported %r fingerprint=%s", row.name, row.gpg_fingerprint)
        imported += 1

    return SeedSummary(imported=imported, skipped_duplicate=skipped, failed=failed)


@dataclass(frozen=True)
class _NameTag:
    name: str
    gpg_fingerprint: str


def _peek_fingerprint(armored: str, name: str) -> str:
    """Best-effort fingerprint extraction for skip-log messages.

    Reuses the same helper the service uses for canonical extraction;
    on any failure (malformed body, gpg unavailable) returns a
    placeholder string so the duplicate-skip log line stays useful.
    """
    try:
        from app.services import mirror_gpg

        with mirror_gpg.ephemeral_gnupg_home() as home:
            return mirror_gpg.import_public_and_extract_fingerprint(home, armored)
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("couldn't peek fingerprint for %r: %s", name, exc)
        return "<unknown>"


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Import Praxis upstream-archive trust anchors from a JSON "
            "seed file (PRA-158 #4c)."
        )
    )
    parser.add_argument(
        "--seed",
        type=Path,
        default=DEFAULT_SEED_PATH,
        help=f"Path to seed JSON (default: {DEFAULT_SEED_PATH})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        summary = import_seed(args.seed, db)
    finally:
        db.close()

    logger.info(
        "seed import complete: imported=%d skipped_duplicate=%d failed=%d",
        summary.imported,
        summary.skipped_duplicate,
        len(summary.failed),
    )
    for f in summary.failed:
        logger.error("failure: %s", f)
    return 0 if not summary.failed else 1


if __name__ == "__main__":
    sys.exit(main())
