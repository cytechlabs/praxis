"""Sign + write the airgap bundle descriptor (PRA-160 slice #1).

The descriptor body is canonical-bytes serialized via
``schema.serialize_descriptor``, signed with the active bundle key
loaded into an ephemeral GNUPGHOME, and written to disk inside
``.airgap-staging/<bundle_id>/`` along with its detached signature.

Locks (PRA-160 design conversation):
  * Reuses the PRA-158 ephemeral GNUPGHOME contract — same
    forbidden-prefix guard, same wipe-on-exit, same fingerprint
    match check before signing.
  * Detached signature only. Clearsign would force the operator to
    hand-extract the JSON body before the importer could parse it,
    and we want the body to be a regular JSON file inspectable with
    ``cat``/``jq``.
  * NEVER logs key material. NEVER logs descriptor body content
    (even though a descriptor is non-secret, it's bulky and noisy
    in logs).
  * **Atomic pair write**: ``bundle.json`` and
    ``bundle.json.sig`` are staged into a sibling
    ``<bundle_id>.new/`` directory and the directory is
    ``os.rename``-promoted into ``<bundle_id>/`` only after BOTH
    files land on disk. A crash or concurrent reader either sees
    the prior pair (or nothing) or the new pair — never a
    half-written body without its sig, or sig pointing at a
    body that doesn't match. Slice #2's re-sign reuses this same
    primitive when populating ``payload_index``.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Tuple

from ...db.models import AirgapBundleSigningKey
from .. import mirror_gpg
from .paths import (
    DESCRIPTOR_FILENAME,
    DESCRIPTOR_SIGNATURE_FILENAME,
    descriptor_path,
    descriptor_signature_path,
    staging_dir,
)
from .schema import BundleDescriptor, serialize_descriptor

logger = logging.getLogger(__name__)


def sign_and_write_descriptor(
    *,
    descriptor: BundleDescriptor,
    signing_key: AirgapBundleSigningKey,
    private_armored: str,
) -> Tuple[Path, Path]:
    """Serialize, sign, and write descriptor + signature to staging.

    Returns ``(descriptor_path, signature_path)`` resolved against the
    final (post-promotion) staging dir.

    Caller fetches ``private_armored`` from Vault. We never persist
    it — it lives only in the ephemeral GNUPGHOME for the duration
    of the sign call.

    Idempotent: re-running overwrites the prior pair atomically.
    The promotion pattern (sibling ``.new/`` → rename → cleanup of
    prior ``.old/``) ensures readers always see a coherent
    ``(body, sig)`` pair.
    """
    body = serialize_descriptor(descriptor)

    with mirror_gpg.ephemeral_gnupg_home() as home:
        mirror_gpg.import_and_verify(home, private_armored, signing_key.gpg_fingerprint)
        sig = mirror_gpg.detached_sign(home, signing_key.gpg_fingerprint, body)

    final_dir = staging_dir(descriptor.bundle_id)
    new_dir = final_dir.with_name(final_dir.name + ".new")
    old_dir = final_dir.with_name(final_dir.name + ".old")

    # Wipe any stale staging artifacts from a prior crashed attempt.
    # Tolerant to missing dirs (first run).
    if new_dir.exists():
        shutil.rmtree(new_dir, ignore_errors=False)
    if old_dir.exists():
        shutil.rmtree(old_dir, ignore_errors=False)

    new_dir.mkdir(parents=True, exist_ok=False)
    new_body = new_dir / DESCRIPTOR_FILENAME
    new_sig = new_dir / DESCRIPTOR_SIGNATURE_FILENAME
    new_body.write_bytes(body)
    new_sig.write_bytes(sig)

    # Promote: rename new → final atomically. If final already exists
    # (re-sign path), shuffle it to .old first; rmtree afterwards.
    # POSIX directory rename is atomic for "rename a non-existing
    # target". A reader between the two renames sees either the old
    # final dir or no final dir (treat-as-missing). The alternative —
    # overlapping in-place writes — has a real half-written window;
    # this pattern eliminates it.
    #
    # If the second rename (new → final) fails after
    # the first rename (final → .old) succeeded, the previously valid
    # descriptor would disappear from the expected path. Roll back by
    # moving .old back to final before re-raising so a failed
    # re-sign leaves the previous descriptor intact.
    moved_to_old = False
    if final_dir.exists():
        os.rename(final_dir, old_dir)
        moved_to_old = True
    try:
        os.rename(new_dir, final_dir)
    except OSError as promote_err:
        if moved_to_old and old_dir.exists() and not final_dir.exists():
            try:
                os.rename(old_dir, final_dir)
                logger.error(
                    "Airgap descriptor promotion failed for bundle_id=%s; "
                    "rolled back prior descriptor from %s to %s.",
                    descriptor.bundle_id,
                    old_dir,
                    final_dir,
                )
            except OSError as restore_err:
                # Worst case: prior valid descriptor is left at .old
                # and slot is empty. Log loudly so an operator can
                # rename manually; we still re-raise the original
                # promotion error to surface root cause.
                logger.error(
                    "Airgap descriptor promotion failed for bundle_id=%s "
                    "AND rollback rename %s -> %s also failed: %s. The "
                    "prior descriptor is at %s; restore manually.",
                    descriptor.bundle_id,
                    old_dir,
                    final_dir,
                    restore_err,
                    old_dir,
                )
        # Always clean up the staging .new dir so a retry isn't
        # blocked by leftover state. Best-effort.
        if new_dir.exists():
            shutil.rmtree(new_dir, ignore_errors=True)
        raise promote_err

    if old_dir.exists():
        try:
            shutil.rmtree(old_dir, ignore_errors=False)
        except OSError as cleanup_err:
            # Cleanup failure is benign: the prior dir is already
            # detached from the read path and a future call (or a
            # cold-start sweep) will reclaim it. Log and move on so
            # an unrelated FS issue doesn't mask the successful
            # promotion.
            logger.warning(
                "Failed to clean up stale airgap staging dir at %s: %s",
                old_dir,
                cleanup_err,
            )

    body_path = descriptor_path(descriptor.bundle_id)
    sig_path = descriptor_signature_path(descriptor.bundle_id)
    logger.info(
        "Wrote signed bundle descriptor bundle_id=%s fingerprint=%s "
        "bytes=%d sig_bytes=%d",
        descriptor.bundle_id,
        signing_key.gpg_fingerprint,
        len(body),
        len(sig),
    )
    return body_path, sig_path
