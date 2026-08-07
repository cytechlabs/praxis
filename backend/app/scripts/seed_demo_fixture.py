"""PRA-184: idempotent synthetic demo fixture for the 1.0 proof path.

Seeds a small, clearly-fictional fleet so the whole lifecycle story renders in
the UI for sales / support / release-QA demos, without depending on whatever
random state happens to be in a developer database.

Run from the repo root (backend container):

    docker compose exec -T backend python -m app.scripts.seed_demo_fixture

Idempotent: every step looks up by a stable key (slug / name / hostname / run
id) and reuses the row if present, so re-running reconciles rather than
duplicates. Survives ``docker compose down`` + fresh ``up`` (re-run it).

Secret-free: the demo credential is a **display-only, non-connectable** row —
no password / key material is written to Vault. The demo never opens SSH; the
patch execution and compliance finding are synthetic rows, not live runs. All
hostnames/IPs are fictional (RFC 5737 TEST-NET-2 ``198.51.100.0/24``).

What it produces, end to end:

1. A ``Demo Fleet`` group + a display-only credential.
2. Three synthetic hosts (``demo-web-01`` Ubuntu 24.04, ``demo-db-01``
   AlmaLinux 9, ``demo-edge-01`` Debian 13), each with a **fresh HostFacts row**
   so the fleet dashboard shows them as *supported* lifecycle (not unknown).
3. One content profile + channel + mirror + ok sync run per host, each indexed
   with a BEFORE and AFTER version of ``curl`` so rollback feasibility resolves.
4. One ``PatchPolicy`` + one approved ``PatchUpdatePlan`` + one plan-host per
   host, plus a succeeded ``PatchUpdateExecution`` (one patch success to show).
5. One failing compliance finding (``auditd`` not installed) on ``demo-web-01``
   plus a ``requested`` remediation request for it.

The rollback feasibility rows are intentionally NOT pre-created — clicking
"Evaluate rollback" on the plan page is part of the operator walkthrough (see
``docs/demo-walkthrough-operator.md``).
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import date, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Keep the ``app`` package importable for non-container reruns; inside the
# backend container ``/app`` is already on sys.path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_APP_PARENT = os.path.normpath(os.path.join(_HERE, "..", ".."))
if os.path.isdir(os.path.join(_APP_PARENT, "app")) and _APP_PARENT not in sys.path:
    sys.path.insert(0, _APP_PARENT)

from app.db.compliance_models import (  # noqa: E402
    CompliancePolicy,
    CompliancePolicyCheck,
    CompliancePolicyEvidence,
    ComplianceRemediationRequest,
)
from app.db.config import DatabaseSettings  # noqa: E402
from app.db.models import (  # noqa: E402
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Distro,
    Group,
    HostFacts,
    MirrorRepo,
    MirrorSyncRun,
    MirrorSyncRunPackage,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    PatchUpdatePlanPreflightSnapshot,
    PatchUpdatePlanSelectedPackage,
    System,
    User,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("seed_demo_fixture")

# --------------------------------------------------------------------------- #
# Constants — all synthetic. IPs are RFC 5737 TEST-NET-2 (documentation-only).
# --------------------------------------------------------------------------- #

DEMO_GROUP_NAME = "Demo Fleet"
CREDENTIAL_NAME = "demo-fixture-cred"
CREDENTIAL_VAULT_PATH = "praxis/credentials/demo-fixture"  # no secret written here
PACKAGE_NAME = "curl"

DEMO_HOSTS = [
    {
        "hostname": "demo-web-01",
        "ip": "198.51.100.11",
        "distro_name": "Ubuntu",
        "distro_version": "24.04",
        "distro_id_facts": "ubuntu",
        "package_family": "deb",
        "package_manager": "apt",
        "pkg_before": "8.5.0-2ubuntu10.1",
        "pkg_after": "8.5.0-2ubuntu10.2",
        "profile_slug": "demo-ubuntu-web",
    },
    {
        "hostname": "demo-db-01",
        "ip": "198.51.100.12",
        "distro_name": "AlmaLinux",
        "distro_version": "9",
        "distro_id_facts": "almalinux",
        "package_family": "rpm",
        "package_manager": "dnf",
        "pkg_before": "7.76.1-29.el9",
        "pkg_after": "7.76.1-31.el9",
        "profile_slug": "demo-almalinux-db",
    },
    {
        "hostname": "demo-edge-01",
        "ip": "198.51.100.13",
        "distro_name": "Debian",
        "distro_version": "13",
        "distro_id_facts": "debian",
        "package_family": "deb",
        "package_manager": "apt",
        "pkg_before": "8.7.1-5",
        "pkg_after": "8.7.1-6",
        "profile_slug": "demo-debian-edge",
    },
]

POLICY_SLUG = "demo-baseline-patch"
PLAN_NAME = "Demo baseline patch plan"
COMPLIANCE_POLICY_SLUG = "demo-baseline-compliance"
COMPLIANCE_CHECK_SLUG = "require-audit-daemon"
COMPLIANCE_RUN_ID = "demo-run"
SEEDED_BY = "seed_demo_fixture"


# --------------------------------------------------------------------------- #
# Idempotent helpers — each returns (obj, created) or just the row.
# --------------------------------------------------------------------------- #


def _get_or_create_admin(db) -> User:
    admin = (
        db.query(User)
        .join(User.roles)
        .filter(User.roles.any(name="admin"))
        .order_by(User.id.asc())
        .first()
    )
    if admin is None:
        admin = db.query(User).order_by(User.id.asc()).first()
    if admin is None:
        raise SystemExit(
            "no User rows exist — run create_admin_user before seeding the demo"
        )
    return admin


def _get_or_create_group(db) -> Group:
    row = db.query(Group).filter(Group.name == DEMO_GROUP_NAME).one_or_none()
    if row is not None:
        return row
    row = Group(name=DEMO_GROUP_NAME, description="Synthetic hosts for the 1.0 demo")
    db.add(row)
    db.flush()
    return row


def _get_or_create_credential(db) -> Credential:
    """A display-only, non-connectable credential. No Vault secret is written —
    the demo never opens SSH, so no key/password material exists."""
    row = db.query(Credential).filter(Credential.name == CREDENTIAL_NAME).one_or_none()
    if row is not None:
        return row
    row = Credential(
        name=CREDENTIAL_NAME,
        auth_method="ssh_key",
        username="demo",
        vault_path=CREDENTIAL_VAULT_PATH,
        sudo_method="none",
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_distro(db, *, name: str, version: str) -> Distro:
    row = (
        db.query(Distro)
        .filter(Distro.name == name, Distro.version == version)
        .one_or_none()
    )
    if row is not None:
        return row
    row = Distro(
        name=name,
        version=version,
        release_date=date(2025, 1, 1),
        end_of_life_date=date(2035, 1, 1),
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_system(
    db, *, host: dict, distro: Distro, credential: Credential, group: Group
) -> System:
    row = db.query(System).filter(System.hostname == host["hostname"]).one_or_none()
    if row is not None:
        return row
    row = System(
        hostname=host["hostname"],
        ip_address=host["ip"],
        distro_id=distro.id,
        os_version=distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=credential.id,
    )
    db.add(row)
    db.flush()
    return row


def _ensure_host_facts(db, *, system: System, host: dict) -> None:
    """A fresh facts row so lifecycle resolves to a real (non-unknown) verdict.
    ``distro_id_facts`` / ``distro_release`` match the DistroLifecycle seed."""
    row = db.query(HostFacts).filter(HostFacts.system_id == system.id).one_or_none()
    now = datetime.utcnow()
    if row is None:
        row = HostFacts(system_id=system.id, schema_version=1, collected_at=now)
        db.add(row)
    # Refresh freshness + distro facts on every run so lifecycle stays green.
    row.collected_at = now
    row.source_transport = "ssh"
    row.distro_id_facts = host["distro_id_facts"]
    row.distro_release = host["distro_version"]
    row.package_manager = host["package_manager"]
    row.reboot_required = False
    db.flush()


def _get_or_create_mirror(
    db, *, slug: str, package_family: str, distribution: str
) -> MirrorRepo:
    row = db.query(MirrorRepo).filter(MirrorRepo.slug == slug).one_or_none()
    if row is not None:
        return row
    row = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family=package_family,
        upstream_url=f"https://example.invalid/{slug}",
        distribution=distribution,
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 4 * * *",
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_ok_run(db, *, mirror: MirrorRepo) -> MirrorSyncRun:
    existing = (
        db.query(MirrorSyncRun)
        .filter(MirrorSyncRun.mirror_repo_id == mirror.id, MirrorSyncRun.status == "ok")
        .order_by(MirrorSyncRun.id.desc())
        .first()
    )
    if existing is not None:
        return existing
    now = datetime.utcnow()
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=now,
        finished_at=now,
        status="ok",
        run_kind="sync",
        byte_count=0,
        package_count=2,
        manifest_sha256="0" * 64,
        manifest_path=f"/var/lib/praxis/mirrors/{mirror.slug}/manifest.json",
    )
    db.add(run)
    db.flush()
    return run


def _ensure_indexed_package(
    db, *, run: MirrorSyncRun, mirror: MirrorRepo, version: str, arch: str = "amd64"
) -> None:
    existing = (
        db.query(MirrorSyncRunPackage)
        .filter(
            MirrorSyncRunPackage.mirror_sync_run_id == run.id,
            MirrorSyncRunPackage.package_name == PACKAGE_NAME,
            MirrorSyncRunPackage.version == version,
            MirrorSyncRunPackage.arch == arch,
        )
        .one_or_none()
    )
    if existing is not None:
        return
    db.add(
        MirrorSyncRunPackage(
            mirror_sync_run_id=run.id,
            mirror_repo_id=mirror.id,
            package_name=PACKAGE_NAME,
            version=version,
            arch=arch,
            filename=f"{PACKAGE_NAME}_{version}_{arch}.pkg",
            sha256="a" * 64,
            size=1024,
        )
    )


def _seed_content_bundle(db, *, host: dict) -> ContentProfile:
    """mirror + ok run + before/after index + channel + profile for one host."""
    slug = host["profile_slug"]
    family = host["package_family"]
    distribution = host["distro_version"] if family == "rpm" else "stable"
    mirror = _get_or_create_mirror(
        db, slug=f"{slug}-mirror", package_family=family, distribution=distribution
    )
    run = _get_or_create_ok_run(db, mirror=mirror)
    _ensure_indexed_package(db, run=run, mirror=mirror, version=host["pkg_before"])
    _ensure_indexed_package(db, run=run, mirror=mirror, version=host["pkg_after"])

    channel = (
        db.query(ContentChannel)
        .filter(
            ContentChannel.slug == f"{slug}-ch", ContentChannel.deleted_at.is_(None)
        )
        .one_or_none()
    )
    if channel is None:
        channel = ContentChannel(
            slug=f"{slug}-ch", display_name=f"{slug}-ch", package_family=family
        )
        db.add(channel)
        db.flush()
    if (
        db.query(ContentChannelRepo)
        .filter(
            ContentChannelRepo.channel_id == channel.id,
            ContentChannelRepo.mirror_id == mirror.id,
            ContentChannelRepo.suite_override.is_(None),
        )
        .one_or_none()
        is None
    ):
        db.add(
            ContentChannelRepo(
                channel_id=channel.id, mirror_id=mirror.id, suite_override=None
            )
        )

    profile = (
        db.query(ContentProfile)
        .filter(ContentProfile.slug == slug, ContentProfile.deleted_at.is_(None))
        .one_or_none()
    )
    if profile is None:
        profile = ContentProfile(slug=slug, display_name=slug, package_family=family)
        db.add(profile)
        db.flush()
    if (
        db.query(ContentProfileChannel)
        .filter(
            ContentProfileChannel.profile_id == profile.id,
            ContentProfileChannel.channel_id == channel.id,
        )
        .one_or_none()
        is None
    ):
        db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    return profile


def _get_or_create_policy(db, *, admin: User) -> PatchPolicy:
    row = db.query(PatchPolicy).filter(PatchPolicy.slug == POLICY_SLUG).one_or_none()
    if row is not None:
        return row
    row = PatchPolicy(
        slug=POLICY_SLUG,
        name="Demo baseline patch policy",
        description="Baseline patch policy for the guided product walkthrough.",
        scope_kind="full",
        scope_packages=[],
        reboot_policy="if_required",
        reboot_window_id=None,
        maintenance_window_id=None,
        rollout_cadence="immediate",
        failure_policy="continue",
        requires_approval=False,
        required_approvals=1,
        enabled=True,
        is_fleet_default=False,
        created_by=admin.id,
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_plan(db, *, policy: PatchPolicy, admin: User) -> PatchUpdatePlan:
    row = (
        db.query(PatchUpdatePlan)
        .filter(
            PatchUpdatePlan.policy_id == policy.id, PatchUpdatePlan.name == PLAN_NAME
        )
        .one_or_none()
    )
    if row is not None:
        return row
    row = PatchUpdatePlan(
        policy_id=policy.id,
        name=PLAN_NAME,
        description="Baseline update plan for the guided product walkthrough.",
        state="approved",
        policy_snapshot={"id": policy.id, "slug": policy.slug, "name": policy.name},
        ring_sequence_snapshot=[],
        request_snapshot={"seeded": True},
        block_reasons=[],
        created_by=admin.id,
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_plan_host(
    db, *, plan: PatchUpdatePlan, system: System, profile: ContentProfile, family: str
) -> PatchUpdatePlanHost:
    row = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.plan_id == plan.id,
            PatchUpdatePlanHost.system_id == system.id,
        )
        .one_or_none()
    )
    if row is not None:
        return row
    row = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=system.id,
        system_hostname_snapshot=system.hostname,
        policy_resolution_kind="direct_host",
        policy_id_snapshot=plan.policy_id,
        policy_slug_snapshot=plan.policy.slug if plan.policy else None,
        ring_resolution_status="not_applicable",
        wave_index=0,
        content_profile_state="resolved",
        content_profile_id_snapshot=profile.id,
        content_profile_slug_snapshot=profile.slug,
        content_profile_display_name_snapshot=profile.display_name,
        content_profile_package_family_snapshot=family,
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(row)
    db.flush()
    return row


def _ensure_selected_package(db, *, plan_host: PatchUpdatePlanHost, host: dict) -> None:
    if (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(
            PatchUpdatePlanSelectedPackage.plan_host_id == plan_host.id,
            PatchUpdatePlanSelectedPackage.package_name == PACKAGE_NAME,
            PatchUpdatePlanSelectedPackage.advisory_id_snapshot.is_(None),
        )
        .one_or_none()
        is not None
    ):
        return
    db.add(
        PatchUpdatePlanSelectedPackage(
            plan_host_id=plan_host.id,
            package_name=PACKAGE_NAME,
            installed_version_snapshot=host["pkg_before"],
            available_version_snapshot=host["pkg_after"],
            advisory_id_snapshot=None,
            selection_reason="policy_full",
            state="selected",
            details={"seeded": True},
        )
    )


def _ensure_preflight(db, *, plan_host: PatchUpdatePlanHost, host: dict) -> None:
    if (
        db.query(PatchUpdatePlanPreflightSnapshot)
        .filter(
            PatchUpdatePlanPreflightSnapshot.plan_host_id == plan_host.id,
            PatchUpdatePlanPreflightSnapshot.package_name == PACKAGE_NAME,
        )
        .one_or_none()
        is not None
    ):
        return
    family_snapshot = "apt" if host["package_family"] == "deb" else "dnf"
    db.add(
        PatchUpdatePlanPreflightSnapshot(
            plan_host_id=plan_host.id,
            package_name=PACKAGE_NAME,
            installed_version_at_preflight=host["pkg_before"],
            package_manager_family_snapshot=family_snapshot,
            content_availability_state="available",
            availability_details={"seeded": True},
            evaluated_at=datetime.utcnow(),
        )
    )


def _get_or_create_execution(
    db, *, plan: PatchUpdatePlan, admin: User
) -> PatchUpdateExecution:
    from sqlalchemy import text as sa_text

    row = (
        db.query(PatchUpdateExecution)
        .filter(
            PatchUpdateExecution.plan_id == plan.id,
            sa_text(f"execution_config_snapshot->>'seeded_by' = '{SEEDED_BY}'"),
        )
        .order_by(PatchUpdateExecution.id.asc())
        .first()
    )
    if row is not None:
        return row
    now = datetime.utcnow()
    row = PatchUpdateExecution(
        plan_id=plan.id,
        state="succeeded",
        started_by=admin.id,
        started_at=now,
        completed_at=now,
        max_parallel_per_wave=1,
        failure_threshold_percent=None,
        plan_state_snapshot=plan.state,
        policy_snapshot=dict(plan.policy_snapshot or {}),
        execution_config_snapshot={"seeded": True, "seeded_by": SEEDED_BY},
        progress_summary={
            "host_total": len(DEMO_HOSTS),
            "host_succeeded": len(DEMO_HOSTS),
        },
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_execution_host(
    db, *, execution: PatchUpdateExecution, plan_host: PatchUpdatePlanHost
) -> PatchUpdateExecutionHost:
    row = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution.id,
            PatchUpdateExecutionHost.plan_host_id == plan_host.id,
        )
        .one_or_none()
    )
    if row is not None:
        return row
    now = datetime.utcnow()
    row = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=plan_host.system_id,
        system_hostname_snapshot=plan_host.system_hostname_snapshot,
        wave_index=plan_host.wave_index,
        state="succeeded",
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
        started_at=now,
        completed_at=now,
    )
    db.add(row)
    db.flush()
    return row


def _ensure_execution_host_package(
    db, *, execution_host: PatchUpdateExecutionHost, host: dict
) -> None:
    if (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(
            PatchUpdateExecutionHostPackage.execution_host_id == execution_host.id,
            PatchUpdateExecutionHostPackage.package_name == PACKAGE_NAME,
        )
        .one_or_none()
        is not None
    ):
        return
    family_snapshot = "apt" if host["package_family"] == "deb" else "dnf"
    db.add(
        PatchUpdateExecutionHostPackage(
            execution_host_id=execution_host.id,
            package_name=PACKAGE_NAME,
            requested_version_snapshot=host["pkg_after"],
            installed_version_before=host["pkg_before"],
            installed_version_after=host["pkg_after"],
            package_manager_family_snapshot=family_snapshot,
            outcome="succeeded",
            error_code=None,
            details={"seeded": True},
        )
    )


# --------------------------------------------------------------------------- #
# Compliance + remediation
# --------------------------------------------------------------------------- #


def _get_or_create_compliance_policy(db, *, admin: User) -> CompliancePolicy:
    row = (
        db.query(CompliancePolicy)
        .filter(CompliancePolicy.slug == COMPLIANCE_POLICY_SLUG)
        .one_or_none()
    )
    if row is not None:
        return row
    row = CompliancePolicy(
        slug=COMPLIANCE_POLICY_SLUG,
        name="Demo baseline compliance",
        description="Baseline compliance policy for the guided product walkthrough.",
        severity="high",
        category="custom",
        created_by=admin.id,
        enabled=True,
        version=1,
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_compliance_check(
    db, *, policy: CompliancePolicy
) -> CompliancePolicyCheck:
    row = (
        db.query(CompliancePolicyCheck)
        .filter(
            CompliancePolicyCheck.policy_id == policy.id,
            CompliancePolicyCheck.slug == COMPLIANCE_CHECK_SLUG,
        )
        .one_or_none()
    )
    if row is not None:
        return row
    row = CompliancePolicyCheck(
        policy_id=policy.id,
        slug=COMPLIANCE_CHECK_SLUG,
        title="Audit daemon installed",
        description="Every host should have the audit daemon installed.",
        kind="package_installed",
        definition_json={"package": "auditd"},
        severity_override="high",
        enabled=True,
        display_order=0,
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_evidence(
    db, *, policy: CompliancePolicy, check: CompliancePolicyCheck, system: System
) -> CompliancePolicyEvidence:
    row = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == system.id,
            CompliancePolicyEvidence.check_slug == check.slug,
            CompliancePolicyEvidence.evaluation_run_id == COMPLIANCE_RUN_ID,
        )
        .one_or_none()
    )
    if row is not None:
        return row
    row = CompliancePolicyEvidence(
        policy_id=policy.id,
        check_id=check.id,
        system_id=system.id,
        policy_slug=policy.slug,
        policy_version=policy.version,
        check_slug=check.slug,
        check_kind=check.kind,
        verdict="fail",
        verdict_reason="package 'auditd' is not installed",
        observed_value="absent",
        expected_value="installed",
        severity="high",
        evaluation_run_id=COMPLIANCE_RUN_ID,
        evaluated_at=datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _get_or_create_remediation_request(
    db,
    *,
    policy: CompliancePolicy,
    check: CompliancePolicyCheck,
    evidence: CompliancePolicyEvidence,
    system: System,
    admin: User,
) -> ComplianceRemediationRequest:
    row = (
        db.query(ComplianceRemediationRequest)
        .filter(
            ComplianceRemediationRequest.policy_id == policy.id,
            ComplianceRemediationRequest.system_id == system.id,
            ComplianceRemediationRequest.check_slug == check.slug,
        )
        .order_by(ComplianceRemediationRequest.id.asc())
        .first()
    )
    if row is not None:
        return row
    row = ComplianceRemediationRequest(
        policy_id=policy.id,
        check_id=check.id,
        evidence_id=evidence.id,
        system_id=system.id,
        policy_slug=policy.slug,
        policy_version=policy.version,
        check_slug=check.slug,
        check_kind=check.kind,
        verdict_snapshot="fail",
        severity_snapshot="high",
        verdict_reason_snapshot=evidence.verdict_reason,
        evaluation_run_id=COMPLIANCE_RUN_ID,
        requested_by=admin.id,
        state="requested",
        justification="Demo: install the audit daemon on demo-web-01.",
    )
    db.add(row)
    db.flush()
    return row


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def main() -> int:
    # Do not import app.db.session here: that module starts the Prometheus
    # metrics listener on import, which is already bound in a running backend
    # container. Demo/maintenance scripts should connect quietly.
    engine = create_engine(DatabaseSettings().sync_database_url)
    session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False,
    )
    db = session_local()
    try:
        admin = _get_or_create_admin(db)
        group = _get_or_create_group(db)
        credential = _get_or_create_credential(db)
        log.info(
            "admin id=%d, group '%s' id=%d, credential '%s' id=%d (display-only)",
            admin.id,
            group.name,
            group.id,
            credential.name,
            credential.id,
        )

        for host in DEMO_HOSTS:
            distro = _get_or_create_distro(
                db, name=host["distro_name"], version=host["distro_version"]
            )
            system = _get_or_create_system(
                db, host=host, distro=distro, credential=credential, group=group
            )
            _ensure_host_facts(db, system=system, host=host)
            host["_system"] = system
            host["_profile"] = _seed_content_bundle(db, host=host)
            log.info(
                "host %s id=%d (%s %s) facts+profile seeded",
                system.hostname,
                system.id,
                host["distro_name"],
                host["distro_version"],
            )

        policy = _get_or_create_policy(db, admin=admin)
        plan = _get_or_create_plan(db, policy=policy, admin=admin)
        execution = _get_or_create_execution(db, plan=plan, admin=admin)
        for host in DEMO_HOSTS:
            plan_host = _get_or_create_plan_host(
                db,
                plan=plan,
                system=host["_system"],
                profile=host["_profile"],
                family=host["package_family"],
            )
            _ensure_selected_package(db, plan_host=plan_host, host=host)
            _ensure_preflight(db, plan_host=plan_host, host=host)
            execution_host = _get_or_create_execution_host(
                db, execution=execution, plan_host=plan_host
            )
            _ensure_execution_host_package(db, execution_host=execution_host, host=host)
        log.info(
            "policy id=%d, plan id=%d (state=%s), execution id=%d (state=%s)",
            policy.id,
            plan.id,
            plan.state,
            execution.id,
            execution.state,
        )

        # Compliance finding + remediation on the first host.
        comp_system = DEMO_HOSTS[0]["_system"]
        comp_policy = _get_or_create_compliance_policy(db, admin=admin)
        comp_check = _get_or_create_compliance_check(db, policy=comp_policy)
        evidence = _get_or_create_evidence(
            db, policy=comp_policy, check=comp_check, system=comp_system
        )
        remediation = _get_or_create_remediation_request(
            db,
            policy=comp_policy,
            check=comp_check,
            evidence=evidence,
            system=comp_system,
            admin=admin,
        )
        log.info(
            "compliance policy id=%d, failing evidence id=%d, remediation id=%d "
            "(state=%s) on %s",
            comp_policy.id,
            evidence.id,
            remediation.id,
            remediation.state,
            comp_system.hostname,
        )

        db.commit()
        log.info(
            "demo fixture seeded: plan %d, %d hosts, compliance finding + "
            "remediation. Visit /patch-update-plans/%d and /compliance.",
            plan.id,
            len(DEMO_HOSTS),
            plan.id,
        )
        return 0
    except Exception:  # pylint: disable=broad-except
        db.rollback()
        log.exception("demo fixture seeding failed; rolled back")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
