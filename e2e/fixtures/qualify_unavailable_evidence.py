"""Owned qualification for unavailable compliance evidence on a real host.

Runs inside the backend container (see qualify-unavailable-evidence.sh) against
a disposable sshd target. Phases:

  setup             create this run's group, credential, vault secret, host and
                    policy
  evaluate <step>   evaluate the policy, then verify the persisted evidence
  teardown          delete only what this run created and verify it is gone
  selftest          prove the evidence verification rejects bad result sets

Ownership: every row and the vault path carry the run id (QUAL_RUN_ID), so
runs that overlap, or resources that already exist under other names, are never
read or deleted. The Ubuntu 24.04 distro row is a shared baseline that ships
with the product: it is required to exist, never created and never deleted
here, so concurrent runs cannot strand or remove each other's reference. Vault
absence is only accepted on a 404 for the owned path; an unavailable or denying
service fails the run. Nothing here edits product code or seeded data.
"""

from __future__ import annotations

import os
import re
import sys

from app.db.compliance_models import CompliancePolicy, CompliancePolicyEvidence
from app.db.models import Credential, Distro, Group, System, SystemMetadata
from app.db.session import SessionLocal
from app.db.ssh_security_models import SSHHostKey, SSHSecurityLog
from app.services.compliance_evaluation_service import (
    evaluate_policy_for_host,
    evidence_export_row,
)
from app.services.vault_service import VaultService, _split_path

RUN_ID = os.environ.get("QUAL_RUN_ID", "")
if not re.fullmatch(r"[0-9a-f]{12}", RUN_ID):
    raise SystemExit("QUAL_RUN_ID must be 12 lowercase hex characters")

HOSTNAME = f"e2e-qual-host-{RUN_ID}"
GROUP = f"e2e-qual-group-{RUN_ID}"
CRED = f"e2e-qual-cred-{RUN_ID}"
POLICY_SLUG = f"e2e-qual-policy-{RUN_ID}"
VAULT_PATH = f"praxis/e2e-qual/{RUN_ID}"
DISTRO = ("Ubuntu", "24.04")

CHECKS = {
    # Reads stored host facts: a host that never reported facts has none.
    "facts": ("fact_present", {"fact_key": "host.kernel_version"}),
    # Executes over SSH on the host itself.
    "probe": ("file_exists", {"path": "/etc/passwd"}),
}

# step -> check slug -> (verdict, reason)
EXPECTED = {
    "reachable": {
        "facts": ("error", "no_host_facts_row"),
        "probe": ("pass", None),
    },
    "sshd_stopped": {
        "facts": ("error", "no_host_facts_row"),
        "probe": ("error", "ssh_transport_failure"),
    },
    "recovered": {
        "facts": ("error", "no_host_facts_row"),
        "probe": ("pass", None),
    },
}
# runner_status comes from the evidence export contract (evidence_export_row),
# the same wire shape the operator-facing exports and evidence reads use.
EXPECTED_RUNNER_STATUS = "runner_executed"


class QualificationError(Exception):
    """Raised when the persisted evidence does not match the expectation."""


def verify_rows(rows, expected):
    """Require exactly one row per expected check, then verify each.

    ``rows`` are evidence export rows. An empty result, a missing check, a
    duplicate, or an unexpected extra check all fail.
    """
    if not rows:
        raise QualificationError("no evidence rows were persisted for this run")
    slugs = [r["check_slug"] for r in rows]
    duplicates = sorted({s for s in slugs if slugs.count(s) > 1})
    if duplicates:
        raise QualificationError(f"duplicate evidence for checks: {duplicates}")
    missing = sorted(set(expected) - set(slugs))
    if missing:
        raise QualificationError(f"missing evidence for checks: {missing}")
    extra = sorted(set(slugs) - set(expected))
    if extra:
        raise QualificationError(f"unexpected evidence for checks: {extra}")
    for row in rows:
        want = expected[row["check_slug"]]
        got = (row["verdict"], row["verdict_reason"])
        if got != want:
            raise QualificationError(
                f"{row['check_slug']}: expected {want}, got {got}"
            )
        if row["runner_status"] != EXPECTED_RUNNER_STATUS:
            raise QualificationError(
                f"{row['check_slug']}: runner_status {row['runner_status']}"
            )


def _vault_kv(vault):
    client = vault.get_client()
    if client is None:
        raise QualificationError("vault client unavailable; cannot verify the secret")
    return client.secrets.kv.v2


def _vault_present(vault) -> bool:
    """True when the owned secret exists, False only on a confirmed 404.

    Any other failure (service unavailable, permission denied) is uncertainty
    and is raised instead of being read as absence.
    """
    import hvac.exceptions

    mount, secret = _split_path(VAULT_PATH)
    try:
        _vault_kv(vault).read_secret_version(path=secret, mount_point=mount)
    except hvac.exceptions.InvalidPath:
        return False
    except QualificationError:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        raise QualificationError(
            f"cannot determine whether the vault secret exists: {type(exc).__name__}"
        ) from exc
    return True


def _vault_remove(vault) -> None:
    """Delete the owned secret and confirm absence; raise on uncertainty."""
    mount, secret = _split_path(VAULT_PATH)
    if _vault_present(vault):
        try:
            _vault_kv(vault).delete_metadata_and_all_versions(
                path=secret, mount_point=mount
            )
        except QualificationError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            raise QualificationError(
                f"vault secret delete failed: {type(exc).__name__}"
            ) from exc
    if _vault_present(vault):
        raise QualificationError("vault secret still present after delete")


def _admin_id(db):
    from app.db.models import User

    user = db.query(User).order_by(User.id.asc()).first()
    if user is None:
        raise SystemExit("no administrator exists on this stack")
    return user.id


def setup() -> None:
    from app.services import compliance_service

    db = SessionLocal()
    try:
        # The distro is a shared baseline: require it, never create it, so a
        # missing baseline fails before anything is created.
        distro = db.query(Distro).filter_by(name=DISTRO[0], version=DISTRO[1]).first()
        if distro is None:
            raise QualificationError(
                f"baseline distro {DISTRO[0]} {DISTRO[1]} is not present on this "
                "stack; the qualification does not create shared rows"
            )
        db.add(Group(name=GROUP, description=f"e2e qualification run {RUN_ID}"))
        db.commit()
        group = db.query(Group).filter_by(name=GROUP).one()

        if not VaultService(db).write_secret(
            VAULT_PATH, {"password": os.environ["QUAL_PASSWORD"]}
        ):
            raise QualificationError("vault secret write failed")
        cred = Credential(
            name=CRED,
            auth_method="password",
            username="root",
            vault_path=VAULT_PATH,
        )
        db.add(cred)
        db.flush()
        db.add(
            System(
                hostname=HOSTNAME,
                ip_address=os.environ["QUAL_IP"],
                distro_id=distro.id,
                os_version=DISTRO[1],
                status="Active",
                group_id=group.id,
                credentials_id=cred.id,
            )
        )
        db.commit()
        admin = _admin_id(db)
        policy = compliance_service.create_policy(
            db,
            actor_user_id=admin,
            slug=POLICY_SLUG,
            name=f"e2e qualification policy {RUN_ID}",
        )
        for slug, (kind, definition) in CHECKS.items():
            compliance_service.add_check(
                db,
                policy.id,
                actor_user_id=admin,
                slug=slug,
                title=slug,
                kind=kind,
                definition=definition,
            )
        db.commit()
        print("setup ok")
    finally:
        db.close()


def _tamper(db, run_id, mode):
    """Test hook (QUAL_TAMPER): damage this run's persisted evidence so the
    verification can be shown to reject it."""
    rows = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.evaluation_run_id == run_id)
        .order_by(CompliancePolicyEvidence.id.asc())
        .all()
    )
    if mode == "empty":
        for row in rows:
            db.delete(row)
    elif mode == "missing":
        db.delete(rows[0])
    elif mode == "duplicate":
        first = rows[0]
        db.add(
            CompliancePolicyEvidence(
                **{
                    c.name: getattr(first, c.name)
                    for c in CompliancePolicyEvidence.__table__.columns
                    if c.name not in ("id", "created_at", "updated_at")
                }
            )
        )
    else:
        raise SystemExit(f"unknown QUAL_TAMPER mode {mode}")
    db.commit()


def evaluate(step: str) -> None:
    db = SessionLocal()
    try:
        policy = db.query(CompliancePolicy).filter_by(slug=POLICY_SLUG).one()
        system = db.query(System).filter_by(hostname=HOSTNAME).one()
        summary = evaluate_policy_for_host(
            db, policy_id=policy.id, system_id=system.id
        )
        tamper = os.environ.get("QUAL_TAMPER")
        if tamper:
            _tamper(db, summary.run_id, tamper)
        evidence = (
            db.query(CompliancePolicyEvidence)
            .filter(
                CompliancePolicyEvidence.evaluation_run_id == summary.run_id,
                CompliancePolicyEvidence.policy_id == policy.id,
                CompliancePolicyEvidence.system_id == system.id,
            )
            .all()
        )
        rows = [evidence_export_row(e) for e in evidence]
        for row in sorted(rows, key=lambda r: r["check_slug"]):
            print(
                f"{step}: {row['check_slug']} verdict={row['verdict']} "
                f"reason={row['verdict_reason']} runner={row['runner_status']}"
            )
        try:
            verify_rows(rows, EXPECTED[step])
        except QualificationError as exc:
            print(f"FAIL {step}: {exc}")
            sys.exit(1)
        print(f"PASS {step}")
    finally:
        db.close()


def teardown() -> None:
    """Delete this run's resources only, then verify they are gone.

    Failures are collected rather than hidden. The run's group is the last
    thing removed and is kept when anything earlier failed, so a retry can
    still find and finish the cleanup.
    """
    from app.services import compliance_service

    db = SessionLocal()
    errors = []
    try:
        admin = _admin_id(db)
        policy = db.query(CompliancePolicy).filter_by(slug=POLICY_SLUG).first()
        system = db.query(System).filter_by(hostname=HOSTNAME).first()

        if system is not None:
            db.query(CompliancePolicyEvidence).filter(
                CompliancePolicyEvidence.system_id == system.id
            ).delete(synchronize_session=False)
            db.query(SystemMetadata).filter(
                SystemMetadata.system_id == system.id
            ).delete(synchronize_session=False)
            db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).delete(
                synchronize_session=False
            )
            db.query(SSHSecurityLog).filter(
                SSHSecurityLog.system_id == system.id
            ).delete(synchronize_session=False)
        if policy is not None:
            db.query(CompliancePolicyEvidence).filter(
                CompliancePolicyEvidence.policy_id == policy.id
            ).delete(synchronize_session=False)
            db.commit()
            compliance_service.delete_policy(db, policy.id, actor_user_id=admin)
        if system is not None:
            db.query(System).filter(System.id == system.id).delete()
        db.query(Credential).filter_by(name=CRED).delete()
        db.commit()

        try:
            _vault_remove(VaultService(db))
        except QualificationError as exc:
            errors.append(str(exc))

        if not errors:
            db.query(Group).filter_by(name=GROUP).delete()
            db.commit()

        leftovers = {
            "policy": db.query(CompliancePolicy).filter_by(slug=POLICY_SLUG).count(),
            "system": db.query(System).filter_by(hostname=HOSTNAME).count(),
            "credential": db.query(Credential).filter_by(name=CRED).count(),
            "group": db.query(Group).filter_by(name=GROUP).count(),
        }
        if any(leftovers.values()):
            errors.append(f"resources left behind: {leftovers}")
    finally:
        db.close()
    if errors:
        print("FAIL teardown: " + "; ".join(errors))
        sys.exit(1)
    print("teardown ok: no resources of this run remain (vault 404 confirmed)")


def selftest() -> None:
    """Prove verify_rows rejects bad result sets (no database needed)."""

    def row(slug, verdict, reason, runner=EXPECTED_RUNNER_STATUS):
        return {
            "check_slug": slug,
            "verdict": verdict,
            "verdict_reason": reason,
            "runner_status": runner,
        }

    good = [row("facts", "error", "no_host_facts_row"), row("probe", "pass", None)]
    verify_rows(good, EXPECTED["reachable"])
    bad = {
        "empty": [],
        "missing": good[:1],
        "duplicate": good + [good[1]],
        "extra": good + [row("other", "pass", None)],
        "wrong verdict": [good[0], row("probe", "fail", None)],
        "wrong reason": [row("facts", "error", "other"), good[1]],
        "wrong runner": [good[0], row("probe", "pass", None, "runner_deferred")],
    }
    for name, rows in bad.items():
        try:
            verify_rows(rows, EXPECTED["reachable"])
        except QualificationError as exc:
            print(f"rejected {name}: {exc}")
        else:
            print(f"FAIL selftest: {name} was accepted")
            sys.exit(1)
    print("selftest ok: all bad result sets rejected")


if __name__ == "__main__":
    phase = sys.argv[1]
    if phase == "setup":
        try:
            setup()
        except BaseException:
            # Partial setup: remove what this run already created.
            teardown()
            raise
    elif phase == "evaluate":
        evaluate(sys.argv[2])
    elif phase == "teardown":
        teardown()
    elif phase == "selftest":
        selftest()
    else:
        raise SystemExit(f"unknown phase {phase}")
