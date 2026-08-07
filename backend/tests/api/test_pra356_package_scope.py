"""PRA-356: package-management cohort scoping.

Proves the shared ``resolve_package_scope_ids`` composes a cohort selector
(all / system / static group / smart group) ON TOP of the caller's fleet scope,
and that the scoped package routes (aggregate inventory, updates, security,
search, history) honor it:

- admins are tenant-wide; a scoped caller can never widen past their grants;
- a group/smart-group cohort is INTERSECTED with the caller's scope, so an
  empty or disjoint cohort returns zero rows — never a global fallback;
- aggregate rows carry hostnames so operators can see which host owns each row.
"""

from datetime import datetime

import pytest

from app.db.models import (
    AccessGrant,
    Credential,
    FleetRole,
    Group,
    Package,
    PackageUpdate,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services.access_authorization_service import (
    resolve_package_scope_ids,
    scoped_system_ids,
)

# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra356-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


def _mk_group(db, name):
    g = Group(name=name, description="x")
    db.add(g)
    db.flush()
    return g


def _mk_system(db, seed_distro, group, cred, hostname, ip):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _mk_role(db, name):
    r = FleetRole(
        name=name, login_mode="per_user", allowed_actions_json="[]", os_groups_json="[]"
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role):
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


def _mk_smart_group(db, name, systems):
    sg = SmartGroup(name=name, description="x", rule_json="[]")
    db.add(sg)
    db.flush()
    for s in systems:
        db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=s.id))
    db.commit()
    return sg


def _mk_pkg(db, system, name, sec=False, held=False):
    pkg = Package(
        system_id=system.id,
        name=name,
        installed_version="1.0",
        is_security_critical=sec,
        is_held=held,
    )
    db.add(pkg)
    db.flush()
    return pkg


def _mk_update(db, system, name, sec=False):
    pkg = _mk_pkg(db, system, name, sec=sec)
    db.add(
        PackageUpdate(
            package_id=pkg.id,
            system_id=system.id,
            available_version="2.0",
            update_type="security" if sec else "normal",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def fleet(db, seed_distro, cred):
    """g1={a, c}, g2={b}; smart group sg={a, b}."""
    g1 = _mk_group(db, "pra356-g1")
    g2 = _mk_group(db, "pra356-g2")
    a = _mk_system(db, seed_distro, g1, cred, "pra356-a", "10.56.0.1")
    b = _mk_system(db, seed_distro, g2, cred, "pra356-b", "10.56.0.2")
    c = _mk_system(db, seed_distro, g1, cred, "pra356-c", "10.56.0.3")
    sg = _mk_smart_group(db, "pra356-sg", [a, b])
    return {"g1": g1, "g2": g2, "a": a, "b": b, "c": c, "sg": sg}


# --------------------------------------------------------------- resolver unit


def test_resolve_all_admin_is_none(db, admin_user, fleet):
    assert resolve_package_scope_ids(db, admin_user, "all", None) is None
    # Missing/blank scope_type also means "all".
    assert resolve_package_scope_ids(db, admin_user, None, None) is None


def test_resolve_all_scoped_is_caller_scope(db, maintainer_user, fleet):
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-all"))
    assert resolve_package_scope_ids(db, maintainer_user, "all", None) == {
        fleet["a"].id
    }


def test_resolve_static_group_admin(db, admin_user, fleet):
    got = resolve_package_scope_ids(db, admin_user, "group", fleet["g1"].id)
    assert got == {fleet["a"].id, fleet["c"].id}


def test_resolve_smart_group_admin(db, admin_user, fleet):
    got = resolve_package_scope_ids(db, admin_user, "smart_group", fleet["sg"].id)
    assert got == {fleet["a"].id, fleet["b"].id}


def test_resolve_group_intersects_caller_scope(db, maintainer_user, fleet):
    # Caller can only see A; group g1 is {A, C}. Intersection = {A}.
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-grp"))
    got = resolve_package_scope_ids(db, maintainer_user, "group", fleet["g1"].id)
    assert got == {fleet["a"].id}


def test_resolve_disjoint_cohort_is_empty_not_global(db, maintainer_user, fleet):
    # Caller sees only A; smart group sg is {A, B} but request g2 = {B}. Caller has
    # no grant on B -> empty intersection -> empty set (never None/global).
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-dis"))
    got = resolve_package_scope_ids(db, maintainer_user, "group", fleet["g2"].id)
    assert got == set()


def test_resolve_empty_group_is_empty(db, admin_user, fleet):
    empty = _mk_group(db, "pra356-empty")
    assert resolve_package_scope_ids(db, admin_user, "group", empty.id) == set()


def test_resolve_invalid_scope_type_raises(db, admin_user, fleet):
    with pytest.raises(ValueError):
        resolve_package_scope_ids(db, admin_user, "bogus", 1)


def test_resolve_missing_scope_id_raises(db, admin_user, fleet):
    with pytest.raises(ValueError):
        resolve_package_scope_ids(db, admin_user, "group", None)


def test_resolve_system_scope_intersects(db, maintainer_user, fleet):
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-sys"))
    assert resolve_package_scope_ids(db, maintainer_user, "system", fleet["a"].id) == {
        fleet["a"].id
    }
    # Out-of-scope single system -> empty (fail closed, non-disclosing).
    assert (
        resolve_package_scope_ids(db, maintainer_user, "system", fleet["b"].id) == set()
    )


# --------------------------------------------------------------- routes


def test_inventory_group_scope_returns_only_group_hosts(client, db, admin_user, fleet):
    _mk_pkg(db, fleet["a"], "pkg-a")
    _mk_pkg(db, fleet["b"], "pkg-b")
    _mk_pkg(db, fleet["c"], "pkg-c")
    db.commit()
    _login(client, admin_user)
    body = client.get(
        f"/packages/inventory?scope_type=group&scope_id={fleet['g1'].id}"
    ).json()
    hosts = {row["hostname"] for row in body["packages"]}
    assert hosts == {"pra356-a", "pra356-c"}
    # Rows identify the host, and B (not in g1) is excluded.
    assert all("hostname" in row and "system_id" in row for row in body["packages"])
    assert "pra356-b" not in {row["hostname"] for row in body["packages"]}


def test_inventory_smart_group_scope(client, db, admin_user, fleet):
    _mk_pkg(db, fleet["a"], "pkg-a")
    _mk_pkg(db, fleet["b"], "pkg-b")
    _mk_pkg(db, fleet["c"], "pkg-c")
    db.commit()
    _login(client, admin_user)
    body = client.get(
        f"/packages/inventory?scope_type=smart_group&scope_id={fleet['sg'].id}"
    ).json()
    assert {row["hostname"] for row in body["packages"]} == {"pra356-a", "pra356-b"}


def test_inventory_group_intersects_caller_scope(client, db, maintainer_user, fleet):
    _mk_pkg(db, fleet["a"], "pkg-a")
    _mk_pkg(db, fleet["c"], "pkg-c")
    db.commit()
    # Maintainer can only see A; g1 = {A, C}. Inventory must show only A.
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-inv"))
    _login(client, maintainer_user)
    body = client.get(
        f"/packages/inventory?scope_type=group&scope_id={fleet['g1'].id}"
    ).json()
    assert {row["hostname"] for row in body["packages"]} == {"pra356-a"}
    assert (
        "pra356-c"
        not in client.get(
            f"/packages/inventory?scope_type=group&scope_id={fleet['g1'].id}"
        ).text
    )


def test_updates_all_group_scope(client, db, admin_user, fleet):
    _mk_update(db, fleet["a"], "up-a")
    _mk_update(db, fleet["b"], "up-b")
    _login(client, admin_user)
    rows = client.get(
        f"/packages/updates/all?scope_type=group&scope_id={fleet['g2'].id}"
    ).json()
    assert {r["system_id"] for r in rows} == {fleet["b"].id}


def test_security_all_smart_group_scope(client, db, admin_user, fleet):
    _mk_update(db, fleet["a"], "sec-a", sec=True)
    _mk_update(db, fleet["c"], "sec-c", sec=True)
    _login(client, admin_user)
    rows = client.get(
        f"/packages/security/all?scope_type=smart_group&scope_id={fleet['sg'].id}"
    ).json()
    # sg = {A, B}; only A has a security update here.
    assert {r["system_id"] for r in rows} == {fleet["a"].id}


def test_search_group_scope(client, db, admin_user, fleet):
    _mk_pkg(db, fleet["a"], "openssl")
    _mk_pkg(db, fleet["b"], "openssl")
    db.commit()
    _login(client, admin_user)
    body = client.get(
        f"/packages/search?name=openssl&scope_type=group&scope_id={fleet['g1'].id}"
    ).json()
    assert {r["system_id"] for r in body["results"]} == {fleet["a"].id}
    assert body["total"] == 1


def test_scoped_route_invalid_scope_type_is_400(client, db, admin_user, fleet):
    _login(client, admin_user)
    assert (
        client.get("/packages/inventory?scope_type=bogus&scope_id=1").status_code == 400
    )
    assert client.get("/packages/updates/all?scope_type=group").status_code == 400


def test_inventory_all_admin_sees_fleet(client, db, admin_user, fleet):
    _mk_pkg(db, fleet["a"], "pkg-a")
    _mk_pkg(db, fleet["b"], "pkg-b")
    db.commit()
    _login(client, admin_user)
    body = client.get("/packages/inventory").json()
    hosts = {row["hostname"] for row in body["packages"]}
    assert {"pra356-a", "pra356-b"} <= hosts


def test_inventory_empty_scoped_caller_returns_empty(client, db, auditor_user, fleet):
    _mk_pkg(db, fleet["a"], "pkg-a")
    db.commit()
    # Auditor has no grants -> empty scope -> zero rows, never global.
    assert scoped_system_ids(db, auditor_user) == set()
    _login(client, auditor_user)
    body = client.get("/packages/inventory").json()
    assert body["packages"] == []
    assert body["total"] == 0
