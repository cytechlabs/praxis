"""Host-side trust install for mirror signing keys (PRA-158 #3c).

Writes the mirror's public-key trust bundle into the host's native
keyring location via the existing ``HostTransport`` abstraction
(SSH default, agent opt-in per the PRA-153 transport-preference rules).

Locked terminology (project_pra158_design_locks.md):

  * **Deb hosts:** concatenated armored bundle at
    ``/etc/apt/keyrings/praxis-mirror-<slug>.asc``. Apt's modern
    trust model expects per-source ``signed-by=`` references; PRA-159
    will generate the source list. NEVER ``apt-key add`` (deprecated).
  * **Rpm hosts:** one file per fingerprint at
    ``/etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-<slug>-<fp8>``.
    PRA-158 phrases this as "install key material for future repo
    config" — it does NOT run ``rpm --import``. Host trust requires
    either a future ``.repo`` ``gpgkey=file://...`` reference (PRA-159)
    or an explicit operator ``rpm --import``.

Privilege model: writes to ``/etc/...``
need root. Praxis SSH-managed hosts are commonly registered with a
non-root credential plus a sudo configuration; the existing CA /
principals deployment (``ssh_identity_service``) wraps writes in
``sudo install -m 0644 -o root -g root /dev/stdin DEST`` for exactly
this reason.

Durability protocol: ``install`` is a good
privileged-write building block but is NOT a contractual atomic
temp+rename for updating an existing file — it can create/truncate
the destination while copying. To preserve the last-good keyring on
mid-write or disk-full failure, every file goes through an explicit
two-step:

  1. ``install -m 0644 -o root -g root /dev/stdin <FINAL>.praxis-tmp``
     — body via stdin, written to a same-directory tmp. Final path
     untouched.
  2. ``mv -f <FINAL>.praxis-tmp <FINAL>`` — atomic rename on the same
     filesystem, swaps the new bytes in.

If step 1 fails, best-effort ``rm -f`` cleans the orphan tmp. If
step 2 fails, the final path is preserved at last-good and the tmp
is left for forensic inspection.

The privilege prefix is ``sudo -n`` on SSH (noninteractive — fails
fast with a clear stderr if sudoers requires a password, never hangs
or eats /dev/stdin). Agent transport runs as root per the PRA-153
lock, so no prefix is needed. Hosts whose credential is already root
see ``sudo -n`` as a transparent no-op.

After every successful install the ``host_mirror_trust`` row is
upserted with the full set of installed fingerprints (active +
pending_cutover + rotating_out at the time of install). Slice #5's
cutover hard-gate reads this set to refuse cutover when any host is
missing the pending fingerprint.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from ..db.models import HostMirrorTrust, MirrorRepo, System
from .host_etc_writer import ensure_parent_dir, write_managed_file
from .mirror_signing_key_service import MirrorSigningKeyService

logger = logging.getLogger(__name__)


@dataclass
class HostInstallResult:
    """Outcome of installing the trust bundle on one host."""

    host_id: int
    ok: bool
    installed_fingerprints: List[str]
    written_paths: List[str]
    error_text: Optional[str] = None


def _deb_install_targets(slug: str, bundle_armored: str) -> List[tuple[str, bytes]]:
    return [
        (
            f"/etc/apt/keyrings/praxis-mirror-{slug}.asc",
            bundle_armored.encode("utf-8"),
        )
    ]


def _rpm_install_targets(slug: str, keys) -> List[tuple[str, bytes]]:
    targets: List[tuple[str, bytes]] = []
    for k in keys:
        fp8 = k.gpg_fingerprint[:8].lower()
        path = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-{slug}-{fp8}"
        targets.append((path, k.armored.encode("utf-8")))
    return targets


@dataclass
class _BundleKey:
    """Lightweight (fingerprint, armored) pair used by the rpm path
    so the install primitive doesn't pass ORM rows into helpers.
    """

    gpg_fingerprint: str
    armored: str


async def install_mirror_trust_on_host(
    db,
    mirror: MirrorRepo,
    host: System,
    transport,
) -> HostInstallResult:
    """Install ``mirror``'s trust bundle on ``host`` via ``transport``.

    Caller is responsible for constructing the ``transport`` (via
    ``get_transport(host, broker, ssh_service=...)``). On success,
    upserts the ``host_mirror_trust`` row and returns the list of
    fingerprints written. On any failure, returns ``ok=False`` with
    ``error_text`` populated; ``host_mirror_trust`` is NOT updated so
    the row continues to reflect the last successful install.

    Idempotent: re-running install on a host with an already-installed
    bundle replaces the files atomically per the
    ``install -> .praxis-tmp`` + ``mv -f`` two-step (see "Durability
    protocol" in the module docstring). Files end up mode 0o644,
    root:root — public material, world-readable so apt/dnf helper
    users (e.g. apt's ``_apt``) can read them.
    """
    key_service = MirrorSigningKeyService(db)
    keys = key_service.bundle_public_keys(mirror.id)
    if not keys:
        return HostInstallResult(
            host_id=host.id,
            ok=False,
            installed_fingerprints=[],
            written_paths=[],
            error_text=(
                f"mirror '{mirror.slug}' has no signing keys to install — "
                "bootstrap the signing key first"
            ),
        )

    # Pre-fetch armored material so failures here surface before any
    # remote writes (cleaner partial-state story).
    bundle_keys: List[_BundleKey] = []
    for k in keys:
        try:
            bundle_keys.append(
                _BundleKey(
                    gpg_fingerprint=k.gpg_fingerprint,
                    armored=key_service.get_public_armored(k),
                )
            )
        except RuntimeError as exc:
            return HostInstallResult(
                host_id=host.id,
                ok=False,
                installed_fingerprints=[],
                written_paths=[],
                error_text=f"failed to load public key {k.gpg_fingerprint}: {exc}",
            )

    if mirror.package_family == "deb":
        bundle_armored = "\n".join(b.armored for b in bundle_keys)
        targets = _deb_install_targets(mirror.slug, bundle_armored)
        parent_dirs = ["/etc/apt/keyrings"]
    elif mirror.package_family == "rpm":
        targets = _rpm_install_targets(mirror.slug, bundle_keys)
        parent_dirs = ["/etc/pki/rpm-gpg"]
    else:
        return HostInstallResult(
            host_id=host.id,
            ok=False,
            installed_fingerprints=[],
            written_paths=[],
            error_text=f"unsupported package_family={mirror.package_family!r}",
        )

    # PRA-159 #3 refactor: durability protocol moved to
    # services.host_etc_writer so the source-list writer shares one
    # implementation. ensure_parent_dir + write_managed_file together
    # produce the same ``install -d`` + ``install /dev/stdin tmp`` +
    # ``mv -f`` sequence the inline code used before.
    for parent in parent_dirs:
        parent_res = await ensure_parent_dir(transport, parent=parent)
        if not parent_res.ok:
            return HostInstallResult(
                host_id=host.id,
                ok=False,
                installed_fingerprints=[],
                written_paths=[],
                error_text=parent_res.error_text,
            )

    final_paths: List[str] = []
    for path, body in targets:
        write_res = await write_managed_file(
            transport, path=path, body=body, mode="0644"
        )
        if not write_res.ok:
            return HostInstallResult(
                host_id=host.id,
                ok=False,
                installed_fingerprints=[],
                written_paths=[],
                error_text=write_res.error_text,
            )
        final_paths.append(path)

    fingerprints = [b.gpg_fingerprint for b in bundle_keys]
    _upsert_host_trust(db, host.id, mirror.id, fingerprints)

    logger.info(
        "install_mirror_trust: host=%d mirror=%s wrote %d file(s) for %d key(s) "
        "via transport=%s privilege=%s",
        host.id,
        mirror.slug,
        len(final_paths),
        len(fingerprints),
        getattr(transport, "name", "?"),
        "agent" if getattr(transport, "name", None) == "agent" else "sudo",
    )
    return HostInstallResult(
        host_id=host.id,
        ok=True,
        installed_fingerprints=fingerprints,
        written_paths=final_paths,
    )


def _upsert_host_trust(
    db, host_id: int, mirror_id: int, fingerprints: List[str]
) -> None:
    row = (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host_id, mirror_id=mirror_id)
        .one_or_none()
    )
    now = datetime.utcnow()
    if row is None:
        row = HostMirrorTrust(
            host_id=host_id,
            mirror_id=mirror_id,
            installed_fingerprints=list(fingerprints),
            last_installed_at=now,
        )
        db.add(row)
    else:
        row.installed_fingerprints = list(fingerprints)
        row.last_installed_at = now
    db.commit()
