"""PRA-414: registration persists the fields it used to accept and discard.

Before this change ``description``, ``tags``, ``ssh_port`` and the chosen SSH
security policy were all accepted by the registration API and then dropped: the
port was hardcoded, the policy was always ``Default``, and description and tags
had nowhere to go at all. These tests pin the corrected behavior, and the
omission-versus-null contract that keeps existing callers working.
"""

from datetime import date

import pytest

from app.db.models import Distro, System, SystemMetadata, Tag, system_tag
from app.db.ssh_security_models import SSHSecurityPolicy


@pytest.fixture
def distro(db):
    d = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not d:
        d = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 1),
        )
        db.add(d)
        db.flush()
    return d


@pytest.fixture
def policies(db, admin_user):
    """A Default policy plus a named alternative to select."""
    made = {}
    for name, verify in (("Default", True), ("Strict", True)):
        policy = db.query(SSHSecurityPolicy).filter_by(name=name).first()
        if policy is None:
            policy = SSHSecurityPolicy(
                name=name,
                description=f"{name} policy",
                require_host_key_verification=verify,
                created_by=admin_user.id,
            )
            db.add(policy)
            db.flush()
        made[name] = policy
    return made


def _group(authed_client, name="persist-group"):
    res = authed_client.post("/groups", json={"name": name, "description": "g"})
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _credential(authed_client, name="persist-cred"):
    res = authed_client.post(
        "/credentials",
        json={
            "name": name,
            "auth_method": "password",
            "username": "root",
            "password": "s3cret",
            "sudo_method": "none",
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _body(distro_id, group_id, cred_id, **overrides):
    body = {
        "hostname": "persist-01",
        "ip_address": "10.44.0.10",
        "distro_id": distro_id,
        "status": "Active",
        "group_id": group_id,
        "credentials_id": cred_id,
    }
    body.update(overrides)
    return body


def _tag_names(db, system_id):
    rows = db.execute(
        system_tag.select().where(system_tag.c.system_id == system_id)
    ).fetchall()
    ids = [r.tag_id for r in rows]
    return sorted(t.name for t in db.query(Tag).filter(Tag.id.in_(ids)).all())


class TestCreatePersistsEveryConfirmedField:
    def test_description_tags_port_and_policy_are_stored(
        self, authed_client, db, distro, policies
    ):
        group_id = _group(authed_client)
        cred_id = _credential(authed_client)

        res = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id,
                group_id,
                cred_id,
                description="edge cache node",
                tags=["edge", "cache"],
                ssh_port=2222,
                ssh_security_policy_id=policies["Strict"].id,
                environment="Staging",
            ),
        )
        assert res.status_code == 201, res.text
        system_id = res.json()["id"]

        system = db.query(System).filter_by(id=system_id).first()
        assert system.description == "edge cache node"
        assert system.ssh_security_policy_id == policies["Strict"].id

        metadata = db.query(SystemMetadata).filter_by(system_id=system_id).first()
        assert metadata.ssh_port == 2222
        assert metadata.environment_type == "Staging"

        assert _tag_names(db, system_id) == ["cache", "edge"]

    def test_default_policy_and_port_apply_when_not_chosen(
        self, authed_client, db, distro, policies
    ):
        group_id = _group(authed_client, "default-group")
        cred_id = _credential(authed_client, "default-cred")

        res = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id,
                group_id,
                cred_id,
                hostname="persist-02",
                ip_address="10.44.0.11",
            ),
        )
        assert res.status_code == 201, res.text
        system_id = res.json()["id"]

        system = db.query(System).filter_by(id=system_id).first()
        assert system.ssh_security_policy_id == policies["Default"].id
        metadata = db.query(SystemMetadata).filter_by(system_id=system_id).first()
        assert metadata.ssh_port == 22

    @pytest.mark.parametrize("bad_port", [0, 65536, True, "22"])
    def test_invalid_ssh_port_is_refused(
        self, authed_client, db, distro, policies, bad_port
    ):
        group_id = _group(authed_client, f"bad-port-{bad_port}")
        cred_id = _credential(authed_client, f"bad-port-cred-{bad_port}")
        res = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id,
                group_id,
                cred_id,
                hostname="persist-bad",
                ip_address="10.44.0.90",
                ssh_port=bad_port,
            ),
        )
        assert res.status_code == 422, res.text


class TestOmissionVersusNullOnUpdate:
    """Omitting a field leaves stored state alone; sending null clears it."""

    @pytest.fixture
    def existing(self, authed_client, db, distro, policies):
        group_id = _group(authed_client, "upd-group")
        cred_id = _credential(authed_client, "upd-cred")
        res = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id,
                group_id,
                cred_id,
                hostname="upd-01",
                ip_address="10.44.1.10",
                description="original text",
                tags=["alpha", "beta"],
                ssh_port=2200,
                environment="Production",
            ),
        )
        assert res.status_code == 201, res.text
        return {
            "id": res.json()["id"],
            "group_id": group_id,
            "cred_id": cred_id,
            "distro_id": distro.id,
        }

    def _put(self, authed_client, existing, **overrides):
        body = {
            "hostname": "upd-01",
            "ip_address": "10.44.1.10",
            "distro_id": existing["distro_id"],
            "status": "Active",
            "group_id": existing["group_id"],
            "credentials_id": existing["cred_id"],
        }
        body.update(overrides)
        return authed_client.put(f"/systems/{existing['id']}", json=body)

    def test_omitted_fields_are_left_unchanged(self, authed_client, db, existing):
        # A caller that predates these fields sends none of them.
        res = self._put(authed_client, existing)
        assert res.status_code == 200, res.text

        db.expire_all()
        system = db.query(System).filter_by(id=existing["id"]).first()
        metadata = db.query(SystemMetadata).filter_by(system_id=existing["id"]).first()

        assert system.description == "original text"
        assert metadata.ssh_port == 2200
        assert metadata.environment_type == "Production"
        assert _tag_names(db, existing["id"]) == ["alpha", "beta"]

    def test_explicit_null_clears_description(self, authed_client, db, existing):
        res = self._put(authed_client, existing, description=None)
        assert res.status_code == 200, res.text

        db.expire_all()
        system = db.query(System).filter_by(id=existing["id"]).first()
        assert system.description is None

    def test_explicit_tag_list_replaces_tags(self, authed_client, db, existing):
        res = self._put(authed_client, existing, tags=["gamma"])
        assert res.status_code == 200, res.text
        db.expire_all()
        assert _tag_names(db, existing["id"]) == ["gamma"]

    def test_explicit_empty_tag_list_clears_tags(self, authed_client, db, existing):
        res = self._put(authed_client, existing, tags=[])
        assert res.status_code == 200, res.text
        db.expire_all()
        assert _tag_names(db, existing["id"]) == []

    def test_explicit_port_and_environment_are_written(
        self, authed_client, db, existing
    ):
        res = self._put(
            authed_client, existing, ssh_port=2022, environment="Development"
        )
        assert res.status_code == 200, res.text
        db.expire_all()
        metadata = db.query(SystemMetadata).filter_by(system_id=existing["id"]).first()
        assert metadata.ssh_port == 2022
        assert metadata.environment_type == "Development"

    def test_clearing_the_policy_fails_closed_rather_than_opting_out(
        self, authed_client, db, existing
    ):
        """A null policy is 'no named policy', which the connection path reads
        as verification required. It must never become an opt-out."""
        res = self._put(authed_client, existing, ssh_security_policy_id=None)
        assert res.status_code == 200, res.text

        db.expire_all()
        system = db.query(System).filter_by(id=existing["id"]).first()
        assert system.ssh_security_policy_id is None

        from app.services.onboarding_preflight_service import (
            policy_requires_host_key_verification,
        )

        assert policy_requires_host_key_verification(system.ssh_security_policy)


class TestDuplicateAddressIsRejected:
    def test_second_system_with_same_ip_is_refused(
        self, authed_client, db, distro, policies
    ):
        group_id = _group(authed_client, "dup-group")
        cred_id = _credential(authed_client, "dup-cred")
        first = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id, group_id, cred_id, hostname="dup-a", ip_address="10.44.2.10"
            ),
        )
        assert first.status_code == 201, first.text

        second = authed_client.post(
            "/systems/add-system",
            json=_body(
                distro.id, group_id, cred_id, hostname="dup-b", ip_address="10.44.2.10"
            ),
        )
        assert second.status_code == 409, second.text
