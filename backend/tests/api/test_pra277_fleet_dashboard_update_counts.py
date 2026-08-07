"""PRA-277: fleet dashboard update-count semantics.

The fleet dashboard must distinguish the number of SYSTEMS affected by pending
updates from the number of pending package-update ROWS. A fleet can carry
hundreds of pending updates across only a handful of systems, so
``patch_compliance.with_updates`` (distinct systems) must never be presented as a
package-update total. ``HealthService.get_fleet_dashboard`` now also exposes
``pending_package_updates`` / ``pending_security_updates`` (row totals) alongside
the existing systems-affected counts.

These tests build datasets where rows and affected systems diverge and assert
both dimensions independently.
"""

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services.health_service import HealthService


def _make_system(db, seed_distro, hostname, ip):
    g = Group(name=f"pra277-{hostname}", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name=f"pra277-{hostname}-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _add_updates(db, system, *, normal, security):
    """Attach ``normal`` non-security and ``security`` security pending updates to
    ``system``, each backed by its own Package row."""
    for i in range(normal + security):
        update_type = "security" if i < security else "normal"
        pkg = Package(
            system_id=system.id,
            name=f"{system.hostname}-pkg-{i}",
            installed_version="1.0",
            is_security_critical=(update_type == "security"),
        )
        db.add(pkg)
        db.flush()
        db.add(
            PackageUpdate(
                package_id=pkg.id,
                system_id=system.id,
                available_version="2.0",
                update_type=update_type,
                discovered_on=datetime.utcnow(),
            )
        )
    db.flush()


def test_row_totals_and_affected_systems_diverge(db, seed_distro):
    # 3 systems; A: 4 updates (2 security), B: 2 updates (1 security), C: none.
    a = _make_system(db, seed_distro, "pra277-a.example.com", "10.0.0.1")
    b = _make_system(db, seed_distro, "pra277-b.example.com", "10.0.0.2")
    _make_system(db, seed_distro, "pra277-c.example.com", "10.0.0.3")
    _add_updates(db, a, normal=2, security=2)
    _add_updates(db, b, normal=1, security=1)
    db.commit()

    pc = HealthService(db).get_fleet_dashboard()["patch_compliance"]

    assert pc["total"] == 3
    # Systems affected (distinct system_id), NOT row totals.
    assert pc["with_updates"] == 2
    assert pc["with_security_updates"] == 2
    # Row totals across all systems.
    assert pc["pending_package_updates"] == 6
    assert pc["pending_security_updates"] == 3
    # C has nothing pending.
    assert pc["up_to_date"] == 1


def test_security_rows_on_single_system_still_count_all_rows(db, seed_distro):
    # Security updates concentrated on ONE system: systems_with_security == 1 but
    # the row total must reflect every security row.
    a = _make_system(db, seed_distro, "pra277-sec-a.example.com", "10.1.0.1")
    b = _make_system(db, seed_distro, "pra277-sec-b.example.com", "10.1.0.2")
    _add_updates(db, a, normal=1, security=3)  # 3 security rows on A
    _add_updates(db, b, normal=2, security=0)  # B has only normal updates
    db.commit()

    pc = HealthService(db).get_fleet_dashboard()["patch_compliance"]

    assert pc["total"] == 2
    assert pc["with_updates"] == 2  # both A and B have pending updates
    assert pc["with_security_updates"] == 1  # only A has security rows
    assert pc["pending_package_updates"] == 6  # 4 on A + 2 on B
    assert pc["pending_security_updates"] == 3  # all on A
    assert pc["up_to_date"] == 0


def test_no_updates_is_all_up_to_date(db, seed_distro):
    _make_system(db, seed_distro, "pra277-clean-a.example.com", "10.2.0.1")
    _make_system(db, seed_distro, "pra277-clean-b.example.com", "10.2.0.2")
    db.commit()

    pc = HealthService(db).get_fleet_dashboard()["patch_compliance"]

    assert pc["total"] == 2
    assert pc["up_to_date"] == 2
    assert pc["with_updates"] == 0
    assert pc["with_security_updates"] == 0
    assert pc["pending_package_updates"] == 0
    assert pc["pending_security_updates"] == 0


@pytest.mark.parametrize(
    "normal,security,exp_pkg,exp_sec",
    [
        (1, 0, 1, 0),  # singular package update, no security
        (0, 1, 1, 1),  # singular security update
    ],
)
def test_singular_counts(db, seed_distro, normal, security, exp_pkg, exp_sec):
    a = _make_system(
        db, seed_distro, f"pra277-one-{normal}{security}.example.com", "10.3.0.1"
    )
    _add_updates(db, a, normal=normal, security=security)
    db.commit()

    pc = HealthService(db).get_fleet_dashboard()["patch_compliance"]

    assert pc["with_updates"] == 1
    assert pc["pending_package_updates"] == exp_pkg
    assert pc["pending_security_updates"] == exp_sec
