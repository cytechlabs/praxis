"""PRA-163 slice 1 — advisory schema + native-source import service tests.

Covers:

* Per-source-kind normalizers (`ubuntu_usn`, `debian_security`,
  `redhat_updateinfo`) turn native payload shapes into the canonical
  shape with severity normalized, source identity preserved, and
  per-release fixed-package targets expanded.
* Severity vocabulary mapping (Important → high, Moderate → medium,
  unrecognized → unknown).
* CHECK constraints on source_kind / advisory_class / severity /
  distro_family / import status enforced at the DB layer.
* Unique constraint on (source_kind, source_advisory_id) — same
  USN ID under a different source_kind is allowed (source identity
  not collapsed).
* Unique constraint on
  (advisory_id, distro_id, distro_release, package_name) for
  fixed-package targets.
* Idempotency: a repeated import with the same raw payload is a
  digest-equal no-op (no row mutation, no audit, ``unchanged``
  outcome).
* Refresh: a re-import with mutated raw payload updates fields,
  replaces the fixed-package set, and emits ``patch_advisory.refreshed``.
* CASCADE: deleting an advisory cascades fixed_packages.
* Per-payload error isolation: one bad payload yields ``partial``
  status with the rest imported.
* Audit shape: ``patch_advisory.imported`` and
  ``patch_advisory.refreshed`` carry source_kind, source_advisory_id,
  advisory_class, severity, fixed_packages count, and use safe_emit
  with no ``db=``.
* Read helpers: list/filter advisories, list fixed_packages, list
  import runs.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import PatchAdvisory, PatchAdvisoryFixedPackage, PatchAdvisoryImport
from app.services import patch_advisory_service
from app.services.patch_advisory_service import (
    ADVISORY_CLASS_BUGFIX,
    ADVISORY_CLASS_ENHANCEMENT,
    ADVISORY_CLASS_OTHER,
    ADVISORY_CLASS_SECURITY,
    AUDIT_PATCH_ADVISORY_IMPORTED,
    AUDIT_PATCH_ADVISORY_REFRESHED,
    DISTRO_FAMILY_DEBIAN,
    DISTRO_FAMILY_RHEL,
    IMPORT_STATUS_FAILED,
    IMPORT_STATUS_PARTIAL,
    IMPORT_STATUS_SUCCESS,
    SEVERITY_HIGH,
    SOURCE_KIND_DEBIAN_SECURITY,
    SOURCE_KIND_REDHAT_UPDATEINFO,
    SOURCE_KIND_UBUNTU_USN,
    CanonicalAdvisoryPayload,
    PatchAdvisoryError,
    normalize_debian_security,
    normalize_redhat_updateinfo,
    normalize_severity,
    normalize_ubuntu_usn,
)

# -- Native-source fixture payloads ---------------------------------------


def _usn_raw(advisory_id: str = "USN-7234-1", **overrides):
    raw = {
        "id": advisory_id,
        "title": "OpenSSL vulnerabilities",
        "summary": "Several security issues were fixed in OpenSSL.",
        "severity": "High",
        "cves": ["CVE-2026-1234", "CVE-2026-1235"],
        "references": ["https://ubuntu.com/security/notices/" + advisory_id],
        "published": "2026-04-12T00:00:00Z",
        "updated": "2026-04-13T00:00:00Z",
        "release_packages": {
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
            "noble": [
                {"name": "openssl", "version": "3.0.13-0ubuntu1"},
            ],
        },
    }
    raw.update(overrides)
    return raw


def _dsa_raw(advisory_id: str = "DSA-5512-1", **overrides):
    raw = {
        "id": advisory_id,
        "title": "openssl - security update",
        "description": "Multiple vulnerabilities in OpenSSL.",
        "severity": "important",
        "cves": ["CVE-2026-1234"],
        "date": "2026-04-12",
        "releases": {
            "bookworm": {
                "fixed_version": "3.0.13-1~deb12u1",
                "packages": ["openssl", "libssl3"],
            },
        },
    }
    raw.update(overrides)
    return raw


def _rhsa_raw(advisory_id: str = "RHSA-2026:1234", **overrides):
    raw = {
        "id": advisory_id,
        "type": "security",
        "severity": "Important",
        "title": "Important: openssl security update",
        "description": "An update for openssl is available.",
        "issued": "2026-04-12",
        "updated": "2026-04-13",
        "release": "9",
        "distro_id": "rhel",
        "references": [
            {
                "type": "cve",
                "id": "CVE-2026-1234",
                "href": "https://access.redhat.com/security/cve/CVE-2026-1234",
            },
            {"type": "self", "href": "https://access.redhat.com/errata/" + advisory_id},
        ],
        "packages": [
            {"name": "openssl", "version": "3.0.7-25.el9_3"},
            {"name": "openssl-libs", "version": "3.0.7-25.el9_3"},
        ],
    }
    raw.update(overrides)
    return raw


# -- Severity normalization -----------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Critical", "critical"),
        ("HIGH", "high"),
        ("Important", "high"),  # Red Hat / Debian
        ("Moderate", "medium"),
        ("medium", "medium"),
        ("Low", "low"),
        ("Negligible", "negligible"),
        ("None", "negligible"),
        ("Unknown", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
        ("garbage-value", "unknown"),
    ],
)
def test_normalize_severity_maps_native_vocab(raw, expected):
    assert normalize_severity(raw) == expected


# -- Ubuntu USN normalizer ------------------------------------------------


def test_normalize_ubuntu_usn_canonical_shape():
    payload = normalize_ubuntu_usn(_usn_raw())
    assert payload.source_kind == SOURCE_KIND_UBUNTU_USN
    assert payload.source_advisory_id == "USN-7234-1"
    assert payload.advisory_class == ADVISORY_CLASS_SECURITY
    assert payload.severity == SEVERITY_HIGH
    assert payload.distro_family == DISTRO_FAMILY_DEBIAN
    assert payload.title == "OpenSSL vulnerabilities"
    assert payload.cve_ids == ["CVE-2026-1234", "CVE-2026-1235"]
    assert payload.published_at == datetime.fromisoformat("2026-04-12T00:00:00+00:00")
    # Per-release fixed packages expanded.
    targets = {
        (e["distro_release"], e["package_name"]): e["fixed_version"]
        for e in payload.fixed_packages
    }
    assert targets[("jammy", "openssl")] == "3.0.2-0ubuntu1.15"
    assert targets[("jammy", "libssl3")] == "3.0.2-0ubuntu1.15"
    assert targets[("noble", "openssl")] == "3.0.13-0ubuntu1"


def test_normalize_ubuntu_usn_missing_id_rejected():
    with pytest.raises(PatchAdvisoryError, match="missing 'id'"):
        normalize_ubuntu_usn({"title": "x"})


def test_normalize_ubuntu_usn_release_packages_must_be_dict():
    with pytest.raises(PatchAdvisoryError, match="release_packages"):
        normalize_ubuntu_usn({"id": "USN-1-1", "release_packages": []})


# -- Debian Security normalizer -------------------------------------------


def test_normalize_debian_security_canonical_shape():
    payload = normalize_debian_security(_dsa_raw())
    assert payload.source_kind == SOURCE_KIND_DEBIAN_SECURITY
    assert payload.source_advisory_id == "DSA-5512-1"
    assert payload.advisory_class == ADVISORY_CLASS_SECURITY
    assert payload.severity == SEVERITY_HIGH  # important → high
    assert payload.distro_family == DISTRO_FAMILY_DEBIAN
    targets = {
        (e["distro_id"], e["distro_release"], e["package_name"]): e["fixed_version"]
        for e in payload.fixed_packages
    }
    assert targets[("debian", "bookworm", "openssl")] == "3.0.13-1~deb12u1"
    assert targets[("debian", "bookworm", "libssl3")] == "3.0.13-1~deb12u1"


# -- Red Hat updateinfo normalizer ----------------------------------------


def test_normalize_redhat_updateinfo_canonical_shape():
    payload = normalize_redhat_updateinfo(_rhsa_raw())
    assert payload.source_kind == SOURCE_KIND_REDHAT_UPDATEINFO
    assert payload.source_advisory_id == "RHSA-2026:1234"
    assert payload.advisory_class == ADVISORY_CLASS_SECURITY
    assert payload.severity == SEVERITY_HIGH  # Important → high
    assert payload.distro_family == DISTRO_FAMILY_RHEL
    assert payload.cve_ids == ["CVE-2026-1234"]
    # External refs include both CVE href + self href.
    assert any("CVE-2026-1234" in r for r in payload.external_refs)
    assert any("/errata/" in r for r in payload.external_refs)
    targets = {
        (e["distro_release"], e["package_name"]): e["fixed_version"]
        for e in payload.fixed_packages
    }
    assert targets[("9", "openssl")] == "3.0.7-25.el9_3"
    assert targets[("9", "openssl-libs")] == "3.0.7-25.el9_3"


@pytest.mark.parametrize(
    "rhsa_type,expected_class",
    [
        ("security", ADVISORY_CLASS_SECURITY),
        ("bugfix", ADVISORY_CLASS_BUGFIX),
        ("enhancement", ADVISORY_CLASS_ENHANCEMENT),
        ("newpackage", ADVISORY_CLASS_OTHER),
        ("garbage", ADVISORY_CLASS_OTHER),
    ],
)
def test_normalize_redhat_updateinfo_class_mapping(rhsa_type, expected_class):
    payload = normalize_redhat_updateinfo(_rhsa_raw(type=rhsa_type))
    assert payload.advisory_class == expected_class


def test_normalize_redhat_updateinfo_skips_packages_without_release_context():
    raw = _rhsa_raw()
    raw.pop("release", None)
    raw["packages"] = [{"name": "openssl", "version": "1.0.0"}]  # no per-pkg release
    payload = normalize_redhat_updateinfo(raw)
    assert payload.fixed_packages == []


# -- Service: import (new advisory) ---------------------------------------


def test_import_new_advisory_creates_row_and_fixed_packages(db, admin_user):
    payload = normalize_ubuntu_usn(_usn_raw())
    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    assert run.status == IMPORT_STATUS_SUCCESS
    assert run.imported_count == 1
    assert run.refreshed_count == 0
    assert run.unchanged_count == 0
    assert run.error_count == 0

    assert [o.action for o in outcomes] == ["imported"]

    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-7234-1",
    )
    assert advisory is not None
    assert advisory.severity == SEVERITY_HIGH
    assert advisory.distro_family == DISTRO_FAMILY_DEBIAN
    assert advisory.cve_ids == ["CVE-2026-1234", "CVE-2026-1235"]
    assert isinstance(advisory.raw, dict)
    assert advisory.raw["id"] == "USN-7234-1"
    assert advisory.digest  # sha256 hex, 64 chars
    assert len(advisory.digest) == 64

    fixed = patch_advisory_service.list_fixed_packages(db, advisory.id)
    assert len(fixed) == 3  # 2 jammy + 1 noble
    assert {(f.distro_release, f.package_name) for f in fixed} == {
        ("jammy", "openssl"),
        ("jammy", "libssl3"),
        ("noble", "openssl"),
    }


# -- Service: idempotent re-import (no-op) --------------------------------


def test_reimport_identical_payload_is_no_op(db, admin_user, monkeypatch):
    payload = normalize_ubuntu_usn(_usn_raw())
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-7234-1",
    )
    original_updated = advisory.updated_at
    original_digest = advisory.digest

    audits: list = []

    def fake_safe_emit(**kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(patch_advisory_service, "safe_emit", fake_safe_emit)

    # Re-import the exact same canonical payload → digest matches → no-op.
    payload2 = normalize_ubuntu_usn(_usn_raw())
    run2, outcomes2 = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload2],
        actor_user_id=admin_user.id,
    )

    assert run2.status == IMPORT_STATUS_SUCCESS
    assert run2.imported_count == 0
    assert run2.refreshed_count == 0
    assert run2.unchanged_count == 1
    assert [o.action for o in outcomes2] == ["unchanged"]

    # No audit on digest-equal no-op.
    assert audits == []

    db.refresh(advisory)
    assert advisory.digest == original_digest
    assert advisory.updated_at == original_updated


# -- Service: refresh on raw payload mutation -----------------------------


def test_reimport_with_changed_payload_refreshes_row_and_replaces_packages(
    db, admin_user, monkeypatch
):
    first = normalize_ubuntu_usn(_usn_raw())
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[first],
        actor_user_id=admin_user.id,
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-7234-1",
    )
    original_advisory_id = advisory.id

    # Upstream republished USN with a new fixed_version and a new release.
    revised_raw = _usn_raw(
        severity="Critical",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.16"}],
            "focal": [{"name": "openssl", "version": "1.1.1f-1ubuntu2.20"}],
        },
    )
    revised = normalize_ubuntu_usn(revised_raw)

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service,
        "safe_emit",
        lambda **kw: audits.append(kw),
    )

    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[revised],
        actor_user_id=admin_user.id,
    )
    assert run.refreshed_count == 1
    assert run.imported_count == 0
    assert [o.action for o in outcomes] == ["refreshed"]

    db.refresh(advisory)
    assert advisory.id == original_advisory_id  # same row, refreshed
    assert advisory.severity == "critical"
    assert advisory.raw == revised_raw

    # Fixed-packages replaced (no stale jammy/libssl3 or noble row).
    fixed = patch_advisory_service.list_fixed_packages(db, advisory.id)
    assert {(f.distro_release, f.package_name, f.fixed_version) for f in fixed} == {
        ("jammy", "openssl", "3.0.2-0ubuntu1.16"),
        ("focal", "openssl", "1.1.1f-1ubuntu2.20"),
    }

    # Audit fired exactly once with refreshed action.
    refreshed_events = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_REFRESHED
    ]
    assert len(refreshed_events) == 1
    ctx = refreshed_events[0]["context"]
    assert ctx["source_kind"] == SOURCE_KIND_UBUNTU_USN
    assert ctx["source_advisory_id"] == "USN-7234-1"
    assert ctx["severity"] == "critical"
    assert ctx["fixed_packages"] == 2


# -- Service: source identity preserved across source_kinds ---------------


def test_same_native_id_under_different_source_kind_is_distinct_row(db, admin_user):
    """USN-1-1 under ubuntu_usn and a hypothetical 'USN-1-1' under
    debian_security would be two independent advisories — the
    (source_kind, source_advisory_id) unique constraint admits both.
    """
    usn_payload = normalize_ubuntu_usn(_usn_raw(advisory_id="ID-COLLISION-1"))
    dsa_raw = _dsa_raw(advisory_id="ID-COLLISION-1")
    dsa_payload = normalize_debian_security(dsa_raw)

    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[usn_payload],
        actor_user_id=admin_user.id,
    )
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_DEBIAN_SECURITY,
        payloads=[dsa_payload],
        actor_user_id=admin_user.id,
    )

    rows = (
        db.query(PatchAdvisory)
        .filter(PatchAdvisory.source_advisory_id == "ID-COLLISION-1")
        .all()
    )
    assert {r.source_kind for r in rows} == {
        SOURCE_KIND_UBUNTU_USN,
        SOURCE_KIND_DEBIAN_SECURITY,
    }


# -- Service: per-payload error isolation ---------------------------------


def test_partial_import_isolates_bad_payload(db, admin_user):
    good = normalize_ubuntu_usn(_usn_raw(advisory_id="USN-GOOD-1"))
    # Bad payload: severity not in canonical vocab; bypass normalizer to
    # construct it directly.
    bad = CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-BAD-1",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity="not-a-real-severity",
        title="bad payload",
        distro_family=DISTRO_FAMILY_DEBIAN,
        raw={"id": "USN-BAD-1"},
        fixed_packages=[],
    )

    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[good, bad],
        actor_user_id=admin_user.id,
    )
    assert run.status == IMPORT_STATUS_PARTIAL
    assert run.imported_count == 1
    assert run.error_count == 1
    actions = sorted(o.action for o in outcomes)
    assert actions == ["error", "imported"]
    error = [o for o in outcomes if o.action == "error"][0]
    assert error.source_advisory_id == "USN-BAD-1"
    assert "severity" in error.error
    assert (
        run.error_details and run.error_details[0]["source_advisory_id"] == "USN-BAD-1"
    )


def test_all_payloads_failing_yields_failed_status(db, admin_user):
    bad = CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-BAD-1",
        advisory_class="not-a-class",
        severity=SEVERITY_HIGH,
        title="bad",
        distro_family=DISTRO_FAMILY_DEBIAN,
        raw={"id": "USN-BAD-1"},
    )
    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[bad],
        actor_user_id=admin_user.id,
    )
    assert run.status == IMPORT_STATUS_FAILED
    assert run.error_count == 1
    assert run.imported_count == 0


def test_empty_payload_batch_records_success_run(db, admin_user):
    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[],
        actor_user_id=admin_user.id,
    )
    assert run.status == IMPORT_STATUS_SUCCESS
    assert run.imported_count == 0
    assert outcomes == []


# -- Service: validation guards -------------------------------------------


def test_import_rejects_unknown_source_kind(db, admin_user):
    with pytest.raises(PatchAdvisoryError, match="source_kind"):
        patch_advisory_service.import_advisories(
            db,
            source_kind="not_a_real_source",
            payloads=[],
            actor_user_id=admin_user.id,
        )


def test_import_rejects_unknown_actor(db):
    with pytest.raises(PatchAdvisoryError, match="actor_user_id"):
        patch_advisory_service.import_advisories(
            db,
            source_kind=SOURCE_KIND_UBUNTU_USN,
            payloads=[],
            actor_user_id=999999,
        )


def test_import_rejects_payload_source_kind_mismatch(db, admin_user):
    payload = normalize_ubuntu_usn(_usn_raw())
    # Run says debian_security, payload says ubuntu_usn → reject.
    with pytest.raises(PatchAdvisoryError, match="does not match"):
        patch_advisory_service.import_advisories(
            db,
            source_kind=SOURCE_KIND_DEBIAN_SECURITY,
            payloads=[payload],
            actor_user_id=admin_user.id,
        )


def test_import_rejects_duplicate_fixed_package_targets(db, admin_user):
    bad = CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-DUPE-1",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity=SEVERITY_HIGH,
        title="dupe",
        distro_family=DISTRO_FAMILY_DEBIAN,
        raw={"id": "USN-DUPE-1"},
        fixed_packages=[
            {
                "distro_id": "ubuntu",
                "distro_release": "jammy",
                "package_name": "openssl",
                "fixed_version": "x",
            },
            {
                "distro_id": "ubuntu",
                "distro_release": "jammy",
                "package_name": "openssl",
                "fixed_version": "y",
            },
        ],
    )
    run, outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[bad],
        actor_user_id=admin_user.id,
    )
    assert run.error_count == 1
    assert "duplicate" in outcomes[0].error


# -- Audit shape -----------------------------------------------------------


def test_imported_audit_event_shape(db, admin_user, monkeypatch):
    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service,
        "safe_emit",
        lambda **kw: audits.append(kw),
    )
    payload = normalize_redhat_updateinfo(_rhsa_raw())
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[payload],
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="127.0.0.1",
    )
    imported = [a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_IMPORTED]
    assert len(imported) == 1
    ev = imported[0]
    # safe_emit called WITHOUT db= per safe_emit-session-boundary feedback.
    assert "db" not in ev
    assert ev["outcome"] == "success"
    assert ev["actor_user_id"] == admin_user.id
    assert ev["actor_username"] == admin_user.username
    assert ev["actor_ip"] == "127.0.0.1"
    assert ev["target_kind"] == "patch_advisory"
    ctx = ev["context"]
    assert ctx["source_kind"] == SOURCE_KIND_REDHAT_UPDATEINFO
    assert ctx["source_advisory_id"] == "RHSA-2026:1234"
    assert ctx["advisory_class"] == ADVISORY_CLASS_SECURITY
    assert ctx["severity"] == SEVERITY_HIGH
    assert ctx["fixed_packages"] == 2


# -- DB constraints --------------------------------------------------------


def test_db_check_rejects_invalid_source_kind(db):
    bad = PatchAdvisory(
        source_kind="not_a_source",
        source_advisory_id="X-1",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity=SEVERITY_HIGH,
        title="x",
        distro_family=DISTRO_FAMILY_DEBIAN,
        digest="0" * 64,
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_check_rejects_invalid_advisory_class(db):
    bad = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="X-2",
        advisory_class="not_a_class",
        severity=SEVERITY_HIGH,
        title="x",
        distro_family=DISTRO_FAMILY_DEBIAN,
        digest="0" * 64,
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_check_rejects_invalid_severity(db):
    bad = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="X-3",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity="not_a_severity",
        title="x",
        distro_family=DISTRO_FAMILY_DEBIAN,
        digest="0" * 64,
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_check_rejects_invalid_distro_family(db):
    bad = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="X-4",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity=SEVERITY_HIGH,
        title="x",
        distro_family="windows",
        digest="0" * 64,
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_unique_constraint_on_source_identity(db, admin_user):
    payload = normalize_ubuntu_usn(_usn_raw(advisory_id="USN-UNIQ-1"))
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    # Direct ORM insert with same (source_kind, source_advisory_id)
    # must fail at the unique constraint.
    dup = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-UNIQ-1",
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity=SEVERITY_HIGH,
        title="dupe",
        distro_family=DISTRO_FAMILY_DEBIAN,
        digest="1" * 64,
    )
    db.add(dup)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_unique_constraint_on_fixed_package_target(db, admin_user):
    payload = normalize_ubuntu_usn(_usn_raw(advisory_id="USN-UNIQ-PKG-1"))
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-UNIQ-PKG-1",
    )
    dup = PatchAdvisoryFixedPackage(
        advisory_id=advisory.id,
        distro_id="ubuntu",
        distro_release="jammy",
        package_name="openssl",  # already present
        fixed_version="x",
    )
    db.add(dup)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_check_rejects_invalid_import_status(db, admin_user):
    bad = PatchAdvisoryImport(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        status="not_a_status",
        started_at=datetime.utcnow(),
        created_by=admin_user.id,
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


# -- CASCADE: deleting advisory removes fixed_packages --------------------


def test_delete_advisory_cascades_fixed_packages(db, admin_user):
    payload = normalize_ubuntu_usn(_usn_raw(advisory_id="USN-CASCADE-1"))
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-CASCADE-1",
    )
    advisory_id = advisory.id
    assert (
        db.query(PatchAdvisoryFixedPackage)
        .filter(PatchAdvisoryFixedPackage.advisory_id == advisory_id)
        .count()
        > 0
    )
    db.delete(advisory)
    db.commit()
    assert (
        db.query(PatchAdvisoryFixedPackage)
        .filter(PatchAdvisoryFixedPackage.advisory_id == advisory_id)
        .count()
        == 0
    )


# -- Read helpers ----------------------------------------------------------


def test_list_advisories_filters(db, admin_user):
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[
            normalize_ubuntu_usn(
                _usn_raw(advisory_id="USN-FILTER-CRIT", severity="Critical")
            ),
            normalize_ubuntu_usn(
                _usn_raw(advisory_id="USN-FILTER-LOW", severity="Low")
            ),
        ],
        actor_user_id=admin_user.id,
    )
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[normalize_redhat_updateinfo(_rhsa_raw(advisory_id="RHSA-FILTER-1"))],
        actor_user_id=admin_user.id,
    )

    crit = patch_advisory_service.list_advisories(db, severity="critical")
    assert {r.source_advisory_id for r in crit} >= {"USN-FILTER-CRIT"}

    rhel_only = patch_advisory_service.list_advisories(
        db, distro_family=DISTRO_FAMILY_RHEL
    )
    assert {r.source_advisory_id for r in rhel_only} >= {"RHSA-FILTER-1"}
    assert all(r.distro_family == DISTRO_FAMILY_RHEL for r in rhel_only)

    by_source = patch_advisory_service.list_advisories(
        db, source_kind=SOURCE_KIND_UBUNTU_USN
    )
    assert all(r.source_kind == SOURCE_KIND_UBUNTU_USN for r in by_source)


def test_list_import_runs_filtered_by_source(db, admin_user):
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[normalize_ubuntu_usn(_usn_raw(advisory_id="USN-RUN-1"))],
        actor_user_id=admin_user.id,
    )
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[normalize_redhat_updateinfo(_rhsa_raw(advisory_id="RHSA-RUN-1"))],
        actor_user_id=admin_user.id,
    )
    usn_runs = patch_advisory_service.list_import_runs(
        db, source_kind=SOURCE_KIND_UBUNTU_USN
    )
    assert usn_runs and all(r.source_kind == SOURCE_KIND_UBUNTU_USN for r in usn_runs)
    rhel_runs = patch_advisory_service.list_import_runs(
        db, source_kind=SOURCE_KIND_REDHAT_UPDATEINFO
    )
    assert rhel_runs and all(
        r.source_kind == SOURCE_KIND_REDHAT_UPDATEINFO for r in rhel_runs
    )
