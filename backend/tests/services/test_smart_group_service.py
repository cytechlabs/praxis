"""Tests for PRA-126 smart group evaluator + cache refresher."""

import json

import pytest

from app.db.models import (
    Credential,
    Group,
    SmartGroup,
    SmartGroupMembership,
    System,
    SystemMetadata,
    Tag,
)
from app.services import smart_group_service as sg

# --- Fixtures --------------------------------------------------------------


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default", description="test")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db, admin_user):
    c = Credential(
        name="t-cred",
        auth_method="password",
        username="root",
        vault_path="vault/path",
    )
    db.add(c)
    db.flush()
    return c


def _mk_system(
    db,
    distro,
    group,
    cred,
    hostname: str,
    ip: str,
    os_version: str = "22.04",
    status: str = "Active",
    ca: bool = False,
):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=distro.id,
        os_version=os_version,
        status=status,
        group_id=group.id,
        credentials_id=cred.id,
        ca_trust_deployed=ca,
    )
    db.add(s)
    db.flush()
    return s


# --- Validator -------------------------------------------------------------


def test_validate_simple_condition_ok():
    sg.validate_rule({"field": "hostname", "op": "eq", "value": "abc"})


def test_validate_group_ok():
    sg.validate_rule(
        {
            "op": "and",
            "rules": [
                {"field": "hostname", "op": "contains", "value": "prod"},
                {"field": "status", "op": "in", "value": ["Active"]},
            ],
        }
    )


def test_validate_unknown_field_rejected():
    with pytest.raises(sg.RuleValidationError):
        sg.validate_rule({"field": "nope", "op": "eq", "value": "x"})


def test_validate_wrong_op_for_field_rejected():
    with pytest.raises(sg.RuleValidationError):
        sg.validate_rule({"field": "hostname", "op": "in", "value": ["x"]})


def test_validate_empty_group_rejected():
    with pytest.raises(sg.RuleValidationError):
        sg.validate_rule({"op": "or", "rules": []})


def test_validate_bad_regex_rejected():
    with pytest.raises(sg.RuleValidationError):
        sg.validate_rule({"field": "hostname", "op": "regex", "value": "[unbalanced"})


# --- Evaluator -------------------------------------------------------------


def test_evaluate_status_in(db, seed_distro, seed_default_group, seed_cred):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "h1", "10.0.0.1")
    s2 = _mk_system(
        db,
        seed_distro,
        seed_default_group,
        seed_cred,
        "h2",
        "10.0.0.2",
        status="Decommissioned",
    )
    db.flush()
    ids = sg.evaluate({"field": "status", "op": "in", "value": ["Active"]}, db)
    assert s1.id in ids and s2.id not in ids


def test_evaluate_hostname_contains(db, seed_distro, seed_default_group, seed_cred):
    s1 = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "prod-web-01", "10.0.0.3"
    )
    s2 = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "dev-web-01", "10.0.0.4"
    )
    db.flush()
    ids = sg.evaluate({"field": "hostname", "op": "contains", "value": "prod"}, db)
    assert s1.id in ids and s2.id not in ids


def test_evaluate_nested_and_or(db, seed_distro, seed_default_group, seed_cred):
    a = _mk_system(
        db,
        seed_distro,
        seed_default_group,
        seed_cred,
        "a",
        "10.1.0.1",
        os_version="22.04",
        ca=True,
    )
    b = _mk_system(
        db,
        seed_distro,
        seed_default_group,
        seed_cred,
        "b",
        "10.1.0.2",
        os_version="20.04",
        ca=False,
    )
    c = _mk_system(
        db,
        seed_distro,
        seed_default_group,
        seed_cred,
        "c",
        "10.1.0.3",
        os_version="22.04",
        ca=False,
    )
    db.flush()
    rule = {
        "op": "and",
        "rules": [
            {"field": "os_version", "op": "eq", "value": "22.04"},
            {
                "op": "or",
                "rules": [
                    {"field": "ca_trust_deployed", "op": "eq", "value": True},
                    {"field": "hostname", "op": "eq", "value": "c"},
                ],
            },
        ],
    }
    ids = sg.evaluate(rule, db)
    assert a.id in ids and c.id in ids and b.id not in ids


def test_evaluate_tag_membership(
    db, seed_distro, seed_default_group, seed_cred, admin_user
):
    tag = Tag(name="prod", color="#ff0000", created_by=admin_user.id)
    db.add(tag)
    db.flush()
    tagged = _mk_system(db, seed_distro, seed_default_group, seed_cred, "x", "10.2.0.1")
    untagged = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "y", "10.2.0.2"
    )
    tagged.tags.append(tag)
    db.flush()
    ids = sg.evaluate({"field": "tag", "op": "in", "value": ["prod"]}, db)
    assert tagged.id in ids and untagged.id not in ids


def test_evaluate_is_case_insensitive(db, seed_distro, seed_default_group, seed_cred):
    """String eq and enum in should match regardless of case (PRA-126 follow-up)."""
    s = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "Prod-Web-01", "10.7.0.1"
    )
    db.flush()
    assert s.id in sg.evaluate(
        {"field": "hostname", "op": "eq", "value": "prod-web-01"}, db
    )
    assert s.id in sg.evaluate({"field": "distro", "op": "in", "value": ["ubuntu"]}, db)
    assert s.id in sg.evaluate({"field": "status", "op": "in", "value": ["active"]}, db)


def test_evaluate_environment_type(db, seed_distro, seed_default_group, seed_cred):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "e1", "10.3.0.1")
    s2 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "e2", "10.3.0.2")
    db.add(SystemMetadata(system_id=s1.id, environment_type="production"))
    db.add(SystemMetadata(system_id=s2.id, environment_type="dev"))
    db.flush()
    ids = sg.evaluate(
        {"field": "environment_type", "op": "in", "value": ["production"]}, db
    )
    assert s1.id in ids and s2.id not in ids


# --- Cache refresh ---------------------------------------------------------


def test_recompute_membership_materialises_rows(
    db, seed_distro, seed_default_group, seed_cred, admin_user
):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "m1", "10.4.0.1")
    s2 = _mk_system(
        db,
        seed_distro,
        seed_default_group,
        seed_cred,
        "m2",
        "10.4.0.2",
        status="Decommissioned",
    )
    group = SmartGroup(
        name="all-active",
        rule_json=json.dumps({"field": "status", "op": "in", "value": ["Active"]}),
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(group)
    db.commit()

    count = sg.recompute_membership(db, group.id)
    assert count == 1

    member_ids = [
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=group.id).all()
    ]
    assert s1.id in member_ids and s2.id not in member_ids


def test_recompute_membership_removes_stale_rows(
    db, seed_distro, seed_default_group, seed_cred, admin_user
):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "s1", "10.5.0.1")
    group = SmartGroup(
        name="ever",
        rule_json=json.dumps({"field": "status", "op": "in", "value": ["Active"]}),
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(group)
    db.commit()
    sg.recompute_membership(db, group.id)
    assert sg.is_member(db, group.id, s1.id) is True

    # Decommission the host — next recompute should drop membership.
    s1.status = "Decommissioned"
    db.commit()
    sg.recompute_membership(db, group.id)
    assert sg.is_member(db, group.id, s1.id) is False
