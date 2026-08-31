"""PRA-155 slice #2a: FactsService.

Single canonical persistence path for fleet inventory facts. Agent
control-tunnel reports, ``/agent/enroll``, the SSH collector (#2b), the
scheduler (#2b), and tests all funnel through ``FactsService.ingest``.

Locked rules (from PRA-155 design lock):

  * One current row per ``system_id``. Upsert; no history v1.
  * Stale-write rejection: if the incoming ``collected_at`` is older
    than the row already on disk, the ingest is no-op'd and recorded
    as ``rejected_stale`` in the audit context. Pass ``force=True``
    to override (debug / out-of-band imports only).
  * No silent merge: each ingest is one collection attempt. Missing
    fields land as NULL on the new row. Fields that the prior row had
    are NOT carried forward — that would mask collector regressions.
    The one exception is the SSH baseline pair
    (``_PRESERVED_EVIDENCE_KEYS``); see the freshness/merge rule below.
  * Freshness/merge rule for the SSH baseline: a collection that reports
    nothing for one of those keys does not erase a value an earlier
    collection established. Transports differ in what they can probe, so
    an absent value means "this run could not establish it", not "the
    host no longer has it". Retention keeps the evidence readable; it
    does not make it current: every carried-forward key is guaranteed a
    ``partial_errors`` coverage entry, supplied by ingestion when the
    collector was too old or too limited to report one itself. Compliance
    evaluation reads that coverage before the value, so a retained value
    is never reported as a fresh observation.
    Preserved keys are named in the audit row and on ``IngestResult`` so
    the carry-forward is never silent, and ``force=True`` bypasses it for
    a deliberate correction.
  * Coverage rule for the SSH baseline: an unreported key is recorded
    whether or not there was a value to retain. With nothing retained the
    column is NULL, and a NULL that says nothing about itself is
    indistinguishable from a host nobody has collected, so a collection
    that ran and could not answer would present as one that never ran.
    The entry is what keeps the two apart, and it makes silent omission
    of a security-relevant value impossible for any transport or
    collector revision.
  * Canonical form for the SSH baseline: values are stored as the single
    lowercased token the server itself reports, so the same setting
    compares equal however the reporting collector obtained it.
  * Unknown payload keys are dropped (forward-compat for newer agents
    pushing fields a back-revved backend doesn't know yet).
  * Cloud metadata sanitizer is the gate. Anything not in the v1
    allowlist (``cloud_provider``, ``instance_id``, ``region``,
    ``zone``) is dropped before write — never log or persist credential
    docs, IAM profile blobs, user-data, SSH keys.
  * Audit emit (``host_facts.ingest``) on every call, success or
    rejection. Cloud metadata in audit context is the SANITIZED dict
    only.
  * ``system_id`` is taken from the trusted caller (mTLS-extracted at
    the broker, or the redeemed activation token). It is NEVER read
    from the facts payload.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import HostFacts, System
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# v1 payload contract version. Bump only on incompatible / semantic
# contract changes — adding a nullable scalar column does NOT require
# a bump because old payloads remain valid (the new field is just
# absent → stored NULL).
SCHEMA_VERSION_V1 = 1

# Valid source-transport enum values. Mirror the migration's CHECK
# constraint; ingest rejects anything outside this set.
VALID_TRANSPORTS = frozenset(("agent", "ssh", "manual"))

# Per-key type contract for allowed scalars. Sanitizer drops values
# that don't match the listed types — a single bad field landing in
# ``partial_errors`` is preferable to a flush() blowup that wipes the
# whole inventory update. ``int``/``bool`` ordering matters because
# ``isinstance(True, int)`` is True in Python, so bool checks happen
# first via the sanitizer's explicit type tuple. Numeric-only fields
# also get a non-negative range check (CHECK constraint mirrors).
#
# Adding a new column? Extend this map AND the upsert assignments
# below; keep the migration's CHECK constraints in sync.
_ALLOWED_SCALAR_TYPES: Dict[str, tuple] = {
    "cpu_model": (str,),
    "cpu_cores": (int,),
    "ram_total_bytes": (int,),
    "kernel_version": (str,),
    "distro_id": (str,),
    "distro_release": (str,),
    "uptime_seconds": (int,),
    "reboot_required": (bool,),
    "package_manager": (str,),
    "package_manager_version": (str,),
    "virtualization": (str,),
    "cloud_provider": (str,),
    # PRA-359: SSH-config + kernel-sysctl scalars (stored as strings — the
    # effective sshd -T / sysctl -n text). Additive nullable; no schema bump.
    "ssh_permit_root_login": (str,),
    "ssh_password_authentication": (str,),
    "sysctl_kernel_randomize_va_space": (str,),
    "sysctl_net_ipv4_ip_forward": (str,),
    "sysctl_net_ipv4_conf_all_rp_filter": (str,),
}
_NONNEG_NUMERIC_KEYS = frozenset({"cpu_cores", "ram_total_bytes", "uptime_seconds"})
_ALLOWED_SCALAR_KEYS = frozenset(_ALLOWED_SCALAR_TYPES.keys())

# The SSH baseline pair: the only keys exempt from the no-carry-forward
# rule.
#
# Every other scalar is inventory: a NULL reads as "unknown" and costs an
# operator nothing. These two decide a security verdict, and not every
# transport or collector revision can probe them. Letting a collection
# that could not establish a value overwrite one that a previous
# collection did establish turns working evidence into a permanent
# coverage gap for the whole fleet, which is exactly the failure the
# no-carry-forward rule was meant to expose elsewhere.
#
# Retention only tells the truth while something records that the latest
# collection did not observe the value, because compliance evaluation
# reads that coverage metadata before it reads a retained value. Ingestion
# guarantees it for every key listed here, so retention does not depend on
# how new or capable the reporting collector is.
#
# The kernel sysctls are deliberately absent. Adding a key here is what
# turns on both retention and the marker, and it is only worth doing for
# facts that decide a verdict; for inventory a NULL already reads as
# "unknown" and retention would add stale values for no gain.
#
# The keys are the payload names, which match their ``HostFacts``
# attribute names.
_PRESERVED_EVIDENCE_KEYS: Tuple[str, ...] = (
    "ssh_permit_root_login",
    "ssh_password_authentication",
)

# The collector's whole-probe coverage key for the SSH baseline. One entry
# under it means neither setting was established, so it already covers both
# and ingestion adds nothing on top. Compliance evaluation matches the same
# key (``FACT_KEY_TO_COLLECTOR_PROBE_KEYS`` in the evaluation service).
_SSH_BASELINE_PROBE_KEY = "ssh_config"

# Coverage reasons recorded when INGESTION, not the collector, noticed that a
# value went unreported. A collector that can tell the difference between
# "could not establish" and "did not look" says so itself and these are never
# used; an older or lower-coverage collector simply omits the field, and these
# markers are what keep the omission visible.
#
# The two cases differ only in what is left on the row. When an earlier value
# was retained, the marker stops it being read as a fresh observation. When
# there was nothing to retain, the marker is the only record that a collection
# ran and could not answer: without it the NULL is indistinguishable from a
# host nobody has scanned yet, and the operator is told to run a scan that
# cannot help.
PRESERVED_WITHOUT_COVERAGE_REASON = "value_not_reported_preserved"
UNREPORTED_WITHOUT_EVIDENCE_REASON = "value_not_reported"

# Allowlisted keys inside ``cloud_instance_metadata``. Anything else
# is dropped by ``_sanitize_cloud_metadata`` before write/audit. Per
# the PRA-155 lock: provider / instance_id / region / zone only.
# Tokens, IAM creds, role docs, user-data, SSH keys, and arbitrary
# vendor dumps are NOT in scope for v1.
_ALLOWED_CLOUD_KEYS = frozenset({"cloud_provider", "instance_id", "region", "zone"})

# Locked v1 disk-entry shape: {mountpoint, filesystem, total_bytes,
# free_bytes}. ``_sanitize_disks`` rebuilds each persisted entry with
# EXACTLY these keys so the storage contract matches the documented
# payload contract — collector-/vendor-specific extras don't leak into
# the canonical row. Entries missing required keys are dropped +
# recorded in ``partial_errors``.
_REQUIRED_DISK_KEYS = ("mountpoint", "filesystem", "total_bytes", "free_bytes")


class FactsIngestError(Exception):
    """Raised for caller-side mistakes that should never happen in
    production code paths (bad transport string, missing system_id).
    Distinct from the silent-no-op ``rejected_stale`` outcome, which is
    a normal runtime condition and returns an ``IngestResult`` instead
    of raising.
    """


@dataclass
class IngestResult:
    """Outcome of a single ``FactsService.ingest`` call.

    ``status`` is one of:
      * ``"upserted"``     — wrote/updated the row.
      * ``"rejected_stale"`` — incoming ``collected_at`` was older than
        the persisted ``collected_at``; no row change.
      * ``"rejected_invalid_timestamp"`` — incoming ``collected_at``
        was missing/unparseable AND a row already existed; refused so
        the fallback ``utcnow()`` can't shadow a real timestamp.
      * ``"noop_empty"``   — payload had no recognized fields after
        sanitization. Treated as a successful poll-with-nothing-to-say
        for audit purposes.

    ``preserved_keys`` names the SSH baseline scalars this collection
    could not establish and whose previously collected value was
    therefore kept. Empty on every other path.
    """

    status: str
    row: Optional[HostFacts]
    rejected_keys: List[str]
    partial_errors: List[Dict[str, Any]]
    preserved_keys: List[str] = field(default_factory=list)


# ----------------------------------------------------------------- helpers


def _sanitize_cloud_metadata(
    raw: Optional[Any],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return (sanitized_dict_or_None, rejected_keys).

    ``None`` is returned when the input is missing, not a dict, or has
    no allowlisted keys after filtering. Rejected keys are returned so
    the audit row can record what was scrubbed (key NAMES only — never
    values).
    """
    if not isinstance(raw, dict):
        return None, []
    out: Dict[str, Any] = {}
    rejected: List[str] = []
    for k, v in raw.items():
        if k in _ALLOWED_CLOUD_KEYS and isinstance(v, (str, int)):
            # Coerce to str; cloud APIs occasionally hand back numerics
            # for region/zone in some flavors, but we store as text.
            out[k] = str(v) if not isinstance(v, str) else v
        else:
            rejected.append(k)
    if not out:
        return None, rejected
    return out, rejected


def _sanitize_disks(
    raw: Optional[Any], partial_errors: List[Dict[str, Any]]
) -> Optional[List[Dict[str, Any]]]:
    """Filter ``raw`` down to entries with the locked v1 shape.

    Output entries contain EXACTLY ``_REQUIRED_DISK_KEYS`` — collector-
    or vendor-specific extras are stripped so the storage contract
    matches the documented payload contract. Bad entries (wrong type,
    missing required keys, non-numeric byte counts) are appended to
    ``partial_errors`` rather than failing the whole ingest.
    """
    if not isinstance(raw, list):
        return None
    out: List[Dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            partial_errors.append({"key": f"disks[{idx}]", "error": "not_an_object"})
            continue
        missing = [k for k in _REQUIRED_DISK_KEYS if k not in entry]
        if missing:
            partial_errors.append(
                {"key": f"disks[{idx}]", "error": f"missing_keys:{','.join(missing)}"}
            )
            continue
        # Reject bool-disguised-as-int for byte counts; isinstance(True, int)
        # is True in Python, but a boolean storage size is nonsense.
        total = entry.get("total_bytes")
        free = entry.get("free_bytes")
        if (
            isinstance(total, bool)
            or isinstance(free, bool)
            or not isinstance(total, (int, float))
            or not isinstance(free, (int, float))
        ):
            partial_errors.append(
                {"key": f"disks[{idx}]", "error": "byte_counts_not_numeric"}
            )
            continue
        # Strip extras: persist exactly the locked v1 shape.
        out.append(
            {
                "mountpoint": entry["mountpoint"],
                "filesystem": entry["filesystem"],
                "total_bytes": total,
                "free_bytes": free,
            }
        )
    return out if out else None


def _sanitize_scalars(
    raw: Dict[str, Any], partial_errors: List[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[str]]:
    """Drop unknown keys and reject type-mismatched allowed keys.

    Returns ``(kept_scalars, rejected_unknown_keys)``. Type mismatches
    on allowed keys land in ``partial_errors`` so a single malformed
    field doesn't poison the whole ingest at flush() time. Range checks
    (non-negative for cpu_cores / ram_total_bytes / uptime_seconds)
    mirror the migration's CHECK constraints, so the DB never sees a
    value it would reject.
    """
    kept: Dict[str, Any] = {}
    rejected_unknown: List[str] = []
    for k, v in raw.items():
        if k in _ALLOWED_SCALAR_KEYS:
            expected = _ALLOWED_SCALAR_TYPES[k]
            # Bool path: only ``reboot_required`` accepts bool. Reject
            # bool-where-int-expected explicitly because Python's bool
            # is a subclass of int and isinstance(True, int) returns
            # True, which would let `cpu_cores: True` past the check.
            if bool not in expected and isinstance(v, bool):
                partial_errors.append(
                    {
                        "key": k,
                        "error": f"type_mismatch:expected_{expected[0].__name__}",
                    }
                )
                continue
            if not isinstance(v, expected):
                partial_errors.append(
                    {
                        "key": k,
                        "error": f"type_mismatch:expected_{expected[0].__name__}",
                    }
                )
                continue
            if k in _NONNEG_NUMERIC_KEYS and v < 0:
                partial_errors.append({"key": k, "error": "negative_value"})
                continue
            kept[k] = v
        elif k in {
            "schema_version",
            "collected_at",
            "disks",
            "cloud_instance_metadata",
            "partial_errors",
        }:
            # Top-level structural keys handled separately; not unknown.
            continue
        else:
            rejected_unknown.append(k)
    return kept, rejected_unknown


def _canonical_evidence_value(raw: Any) -> Optional[str]:
    """Reduce an SSH baseline value to the single lowercased token the
    server itself reports, or ``None`` when nothing usable is left.

    Transports establish these values differently: one reads the server's
    own effective dump, another reads configuration where an administrator's
    capitalization and quoting survive, and a manual import can carry either.
    Storing the same setting two ways would make one host's evidence compare
    unequal to another's for a difference no operator can see, so the
    canonical form is applied here, on the single path every transport
    shares.

    A value that reduces to nothing is not evidence. It is dropped rather
    than stored, which routes it into the same preserve-or-mark handling as
    a value the collection never reported at all.
    """
    if not isinstance(raw, str):
        return None
    tokens = raw.split()
    if not tokens:
        return None
    return tokens[0].strip('"').lower() or None


def _canonicalize_evidence_scalars(scalars: Dict[str, Any]) -> None:
    """Rewrite the SSH baseline scalars in place into their canonical form,
    dropping any that carry no usable value."""
    for key in _PRESERVED_EVIDENCE_KEYS:
        if key not in scalars:
            continue
        canonical = _canonical_evidence_value(scalars[key])
        if canonical is None:
            del scalars[key]
        else:
            scalars[key] = canonical


def _preserved_evidence(
    existing: Optional[HostFacts], scalars: Dict[str, Any]
) -> Dict[str, Any]:
    """Return the SSH baseline values this collection did not establish
    and the previous collection did.

    Only keys absent from ``scalars`` are considered, so a collection
    that reports a value always wins, including when it reports a
    changed one. A key the previous row left NULL stays NULL.
    """
    if existing is None:
        return {}
    preserved: Dict[str, Any] = {}
    for key in _PRESERVED_EVIDENCE_KEYS:
        if scalars.get(key) is not None:
            continue
        prior = getattr(existing, key, None)
        if prior is not None:
            preserved[key] = prior
    return preserved


def _evidence_coverage_markers(
    scalars: Dict[str, Any],
    preserved: Dict[str, Any],
    partial_errors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return the coverage entries ingestion must add for SSH baseline
    scalars this collection did not report.

    Every unreported key gets one, whether or not an earlier value was
    retained, because the two silences mean the same thing: the collection
    ran and could not establish the value. Recording it is what lets
    compliance separate that from a host that has never been scanned, and it
    is the guarantee that a collector too old or too limited to describe its
    own coverage cannot leave a security-relevant value silently missing.

    A collector that does report its own coverage already said this, per key
    or once for the whole probe, and its entry is left alone.
    """
    covered = {
        str(entry.get("key")) for entry in partial_errors if isinstance(entry, dict)
    }
    if _SSH_BASELINE_PROBE_KEY in covered:
        return []
    markers: List[Dict[str, Any]] = []
    for key in _PRESERVED_EVIDENCE_KEYS:
        if scalars.get(key) is not None or key in covered:
            continue
        markers.append(
            {
                "key": key,
                "error": (
                    PRESERVED_WITHOUT_COVERAGE_REASON
                    if key in preserved
                    else UNREPORTED_WITHOUT_EVIDENCE_REASON
                ),
            }
        )
    return markers


def _coerce_collected_at(
    raw: Any, partial_errors: List[Dict[str, Any]]
) -> Tuple[datetime, bool]:
    """Parse ``collected_at`` into a UTC-naive datetime.

    Returns ``(value, fallback_used)``. ``fallback_used`` is True when
    ``raw`` was missing or unparseable and we substituted
    ``datetime.utcnow()``. The caller uses that flag for two things:
      * append a ``collected_at`` entry to ``partial_errors`` so the
        substitution is auditable,
      * tighten stale-write semantics — a fallback timestamp is NOT
        allowed to overwrite an existing row, since "treat unparseable
        as now" would otherwise let a malformed/old report appear
        fresher than a real one.
    """
    if isinstance(raw, datetime):
        return raw, False
    if isinstance(raw, str) and raw:
        try:
            cleaned = raw.rstrip("Z")
            return datetime.fromisoformat(cleaned), False
        except ValueError:
            partial_errors.append(
                {"key": "collected_at", "error": "unparseable_timestamp"}
            )
            return datetime.utcnow(), True
    if raw is None:
        partial_errors.append({"key": "collected_at", "error": "missing_timestamp"})
        return datetime.utcnow(), True
    partial_errors.append({"key": "collected_at", "error": "wrong_type"})
    return datetime.utcnow(), True


# ----------------------------------------------------------------- service


def ingest(
    db: Session,
    *,
    system_id: int,
    payload: Optional[Dict[str, Any]],
    source_transport: str,
    force: bool = False,
) -> IngestResult:
    """Persist a single facts collection attempt.

    ``system_id`` MUST come from a trusted caller (mTLS-extracted at
    the broker, or the redeemed activation-token's resolved system).
    The facts payload is treated as untrusted input even when produced
    by a Praxis-shipped collector — sanitization happens here, not at
    the caller.

    Returns an ``IngestResult``. Audit row emitted in all paths
    (``host_facts.ingest`` action) so every collection attempt is
    visible regardless of outcome.
    """
    if source_transport not in VALID_TRANSPORTS:
        raise FactsIngestError(
            f"source_transport must be one of {sorted(VALID_TRANSPORTS)}, "
            f"got {source_transport!r}"
        )
    if not isinstance(system_id, int) or system_id <= 0:
        raise FactsIngestError(f"system_id must be a positive int, got {system_id!r}")

    # Defensive: confirm the system exists. A missing FK target would
    # raise on flush, but failing fast here keeps the audit row aligned
    # with the actual cause.
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise FactsIngestError(f"system_id={system_id} does not exist")

    payload = payload or {}
    if not isinstance(payload, dict):
        raise FactsIngestError("facts payload must be a dict")

    partial_errors: List[Dict[str, Any]] = []
    # Carry through any caller-supplied per-key errors (the SSH
    # collector and agent collector both produce these).
    caller_errors = payload.get("partial_errors")
    if isinstance(caller_errors, list):
        for entry in caller_errors:
            if isinstance(entry, dict) and "key" in entry and "error" in entry:
                partial_errors.append(
                    {"key": str(entry["key"]), "error": str(entry["error"])}
                )

    scalars, rejected_scalar_keys = _sanitize_scalars(payload, partial_errors)
    # Canonical form first: everything below decides "did this collection
    # report the value?" from ``scalars``, and a value that reduces to
    # nothing must reach those decisions as unreported.
    _canonicalize_evidence_scalars(scalars)
    cloud_md, rejected_cloud_keys = _sanitize_cloud_metadata(
        payload.get("cloud_instance_metadata")
    )
    disks = _sanitize_disks(payload.get("disks"), partial_errors)

    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < 1:
        schema_version = SCHEMA_VERSION_V1

    # "Did the payload TRY to push facts?" — broader than "did valid
    # facts land". Recognized-but-invalid scalar attempts, malformed
    # disk entries, rejected cloud keys, and unknown top-level keys
    # all count: in every one of those cases the agent meant to send
    # inventory and got it wrong. Only a truly empty payload (or one
    # carrying nothing but ``schema_version`` / ``collected_at``)
    # falls through to the ``noop_empty`` path. This is also the gate
    # for the fallback-timestamp rejection below, so an
    # invalid-only payload like ``{"cpu_cores":"x","collected_at":"bad"}``
    # cannot slip past as ``utcnow()`` and overwrite a real row.
    payload_attempted_facts = (
        bool(scalars)
        or cloud_md is not None
        or disks is not None
        or bool(partial_errors)
        or bool(rejected_scalar_keys)
        or bool(rejected_cloud_keys)
    )
    timestamp_errors: List[Dict[str, Any]] = []
    collected_at, collected_at_fallback = _coerce_collected_at(
        payload.get("collected_at"), timestamp_errors
    )
    if payload_attempted_facts:
        partial_errors.extend(timestamp_errors)

    existing = (
        db.query(HostFacts).filter(HostFacts.system_id == system_id).one_or_none()
    )

    # Reject fallback-timestamp ingests when a row already exists AND
    # the payload tried to push facts. Without this, a malformed
    # ``collected_at`` paired with anything fact-shaped (valid OR
    # invalid) would slip past as ``utcnow()`` and overwrite a row
    # whose real timestamp is newer. Empty polls don't trigger this —
    # they fall through to ``noop_empty`` below. ``force=`` overrides
    # for debug/import.
    if (
        not force
        and collected_at_fallback
        and payload_attempted_facts
        and existing is not None
    ):
        _emit(
            db,
            outcome="denied",
            system_id=system_id,
            source_transport=source_transport,
            schema_version=schema_version,
            collected_at=collected_at,
            persisted_collected_at=existing.collected_at,
            rejected_scalar_keys=rejected_scalar_keys,
            rejected_cloud_keys=rejected_cloud_keys,
            partial_error_count=len(partial_errors),
            cloud_metadata=cloud_md,
            reason="rejected_invalid_timestamp",
        )
        return IngestResult(
            status="rejected_invalid_timestamp",
            row=existing,
            rejected_keys=rejected_scalar_keys + rejected_cloud_keys,
            partial_errors=partial_errors,
        )

    # Stale-write rejection: incoming older than persisted. The equal
    # case is allowed (idempotent retry of the same report).
    if (
        not force
        and existing is not None
        and existing.collected_at is not None
        and collected_at < existing.collected_at
    ):
        _emit(
            db,
            outcome="denied",
            system_id=system_id,
            source_transport=source_transport,
            schema_version=schema_version,
            collected_at=collected_at,
            persisted_collected_at=existing.collected_at,
            rejected_scalar_keys=rejected_scalar_keys,
            rejected_cloud_keys=rejected_cloud_keys,
            partial_error_count=len(partial_errors),
            cloud_metadata=cloud_md,
            reason="rejected_stale",
        )
        return IngestResult(
            status="rejected_stale",
            row=existing,
            rejected_keys=rejected_scalar_keys + rejected_cloud_keys,
            partial_errors=partial_errors,
        )

    # No-op for empty payloads (a heartbeat-shaped poll with nothing
    # new). Still audit so the collection attempt is visible.
    has_anything = (
        bool(scalars)
        or cloud_md is not None
        or disks is not None
        or bool(partial_errors)
    )
    if not has_anything:
        _emit(
            db,
            outcome="success",
            system_id=system_id,
            source_transport=source_transport,
            schema_version=schema_version,
            collected_at=collected_at,
            persisted_collected_at=existing.collected_at if existing else None,
            rejected_scalar_keys=rejected_scalar_keys,
            rejected_cloud_keys=rejected_cloud_keys,
            partial_error_count=0,
            cloud_metadata=None,
            reason="noop_empty",
        )
        return IngestResult(
            status="noop_empty",
            row=existing,
            rejected_keys=rejected_scalar_keys + rejected_cloud_keys,
            partial_errors=partial_errors,
        )

    # SSH baseline carry-forward. Read before any assignment below,
    # because ``row`` and ``existing`` are the same object on the update
    # path and the prior values would otherwise already be gone.
    # ``force`` skips it so an out-of-band correction can clear a value.
    preserved = {} if force else _preserved_evidence(existing, scalars)
    # A lower-coverage collector omits a value without saying it could not
    # establish one. Ingestion supplies the missing per-key coverage so an
    # unreported setting is never read as something this collection observed,
    # and never as a host that has simply not been scanned.
    partial_errors.extend(
        _evidence_coverage_markers(scalars, preserved, partial_errors)
    )

    # Upsert. Apart from the preserved SSH baseline scalars we
    # deliberately do NOT carry forward fields from the prior row; each
    # ingest represents one collection attempt and missing fields stay
    # NULL.
    if existing is None:
        row = HostFacts(system_id=system_id)
        db.add(row)
    else:
        row = existing

    row.schema_version = schema_version
    row.collected_at = collected_at
    row.source_transport = source_transport
    row.cpu_model = scalars.get("cpu_model")
    row.cpu_cores = scalars.get("cpu_cores")
    row.ram_total_bytes = scalars.get("ram_total_bytes")
    row.kernel_version = scalars.get("kernel_version")
    row.distro_id_facts = scalars.get("distro_id")
    row.distro_release = scalars.get("distro_release")
    row.uptime_seconds = scalars.get("uptime_seconds")
    row.reboot_required = scalars.get("reboot_required")
    row.package_manager = scalars.get("package_manager")
    row.package_manager_version = scalars.get("package_manager_version")
    row.virtualization = scalars.get("virtualization")
    row.cloud_provider = scalars.get("cloud_provider") or (
        cloud_md.get("cloud_provider") if cloud_md else None
    )
    # SSH baseline scalars. These back compliance verdicts, so an absent
    # value falls back to the last one a collection managed to establish
    # instead of erasing the evidence. Coverage metadata, from the
    # collector or added above on its behalf, decides the verdict; the
    # retained value is kept for traceability, not to be scored.
    for evidence_key in _PRESERVED_EVIDENCE_KEYS:
        value = scalars.get(evidence_key)
        if value is None:
            value = preserved.get(evidence_key)
        setattr(row, evidence_key, value)
    # Kernel sysctls follow the ordinary no-carry-forward rule: no
    # collector reports coverage for them, so a retained value could not
    # be told apart from a freshly observed one.
    row.sysctl_kernel_randomize_va_space = scalars.get(
        "sysctl_kernel_randomize_va_space"
    )
    row.sysctl_net_ipv4_ip_forward = scalars.get("sysctl_net_ipv4_ip_forward")
    row.sysctl_net_ipv4_conf_all_rp_filter = scalars.get(
        "sysctl_net_ipv4_conf_all_rp_filter"
    )
    row.cloud_instance_metadata = cloud_md
    row.disks = disks
    row.partial_errors = partial_errors or None

    db.flush()
    db.commit()
    db.refresh(row)

    _emit(
        db,
        outcome="success",
        system_id=system_id,
        source_transport=source_transport,
        schema_version=schema_version,
        collected_at=collected_at,
        persisted_collected_at=collected_at,
        rejected_scalar_keys=rejected_scalar_keys,
        rejected_cloud_keys=rejected_cloud_keys,
        partial_error_count=len(partial_errors),
        cloud_metadata=cloud_md,
        reason="upserted",
        preserved_keys=sorted(preserved),
    )

    # PRA-155 #2d + PRA-156 #3c: ingest-time scoped recompute. Fires
    # ONLY on a real successful upsert — rejected_stale /
    # rejected_invalid_timestamp / noop_empty paths above already
    # returned without reaching here. The combined helper walks the
    # smart_groups table once and recomputes any group whose rule
    # references EITHER ``facts.*`` (raw fact columns) OR
    # ``lifecycle.*`` (derived from those facts). A mixed-predicate
    # group is touched a single time, not twice.
    #
    # Failures are swallowed: a recompute crash must not fail the
    # ingest (the sweeper is the catch-all).
    try:
        # Lazy import — smart_group_service has its own DB-touching
        # imports and we don't want a circular load chain at module
        # import time.
        from . import smart_group_service

        smart_group_service.recompute_dependent_groups_for_system(db, system_id)
    except Exception:  # pylint: disable=broad-except
        logger.exception(
            "facts ingest: scoped smart-group recompute failed for system_id=%s",
            system_id,
        )

    return IngestResult(
        status="upserted",
        row=row,
        rejected_keys=rejected_scalar_keys + rejected_cloud_keys,
        partial_errors=partial_errors,
        preserved_keys=sorted(preserved),
    )


def _emit(
    db: Session,
    *,
    outcome: str,
    system_id: int,
    source_transport: str,
    schema_version: int,
    collected_at: datetime,
    persisted_collected_at: Optional[datetime],
    rejected_scalar_keys: List[str],
    rejected_cloud_keys: List[str],
    partial_error_count: int,
    cloud_metadata: Optional[Dict[str, Any]],
    reason: str,
    preserved_keys: Optional[List[str]] = None,
) -> None:
    """Audit-row helper. ``cloud_metadata`` is ALREADY sanitized at
    this point; never pass raw payload values here.

    ``preserved_keys`` names SSH baseline scalars kept from the previous
    collection, so a carry-forward is always traceable to the ingest that
    performed it."""
    context: Dict[str, Any] = {
        "system_id": system_id,
        "source_transport": source_transport,
        "schema_version": schema_version,
        "collected_at": collected_at.isoformat() + "Z",
        "partial_error_count": partial_error_count,
        "reason": reason,
    }
    if persisted_collected_at is not None:
        context["persisted_collected_at"] = persisted_collected_at.isoformat() + "Z"
    if rejected_scalar_keys:
        context["rejected_scalar_keys"] = rejected_scalar_keys
    if rejected_cloud_keys:
        context["rejected_cloud_keys"] = rejected_cloud_keys
    if preserved_keys:
        context["preserved_evidence_keys"] = preserved_keys
    if cloud_metadata:
        # Sanitized only — _sanitize_cloud_metadata already filtered.
        context["cloud_metadata"] = cloud_metadata
    safe_emit(
        db=db,
        action="host_facts.ingest",
        outcome=outcome,
        actor_user_id=None,
        target_kind="system",
        target_system_id=system_id,
        target_id=str(system_id),
        context=context,
    )
