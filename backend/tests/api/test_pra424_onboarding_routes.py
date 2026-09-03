"""PRA-424: the discover step decides a host's distribution, once and for all.

Two paths were dead ends. Skipping verification reads nothing from the host, so
the wizard asks the operator to name the distribution, but the confirmation
endpoint refused every request that arrived without a discovery record and the
setup could not be finished at all. And a host with no catalogue mapping was
accepted here on an acknowledgement, then refused at Finish once every other
step had been worked through.

A managed host must resolve to a catalogue row, so the requirement is settled
here: binding to a supported release is the only way through, and there is no
acknowledgement that substitutes for one.

Preflight is substituted here, as in the rest of the onboarding route tests:
these are about the wizard contract rather than about SSH.
"""

from datetime import date

import pytest

from app.api.schemas import onboarding as schemas
from app.db.models import Credential, Distro, Group, System
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="All Systems").first()
    if g is None:
        g = Group(name="All Systems", description="default placement")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def distro(db):
    d = db.query(Distro).filter_by(name="Debian", version="13").first()
    if d is None:
        d = Distro(
            name="Debian",
            version="13",
            release_date=date(2025, 8, 9),
            end_of_life_date=date(2028, 8, 9),
        )
        db.add(d)
        db.flush()
    return d


@pytest.fixture
def default_policy(db, admin_user):
    p = db.query(SSHSecurityPolicy).filter_by(name="Default").first()
    if p is None:
        p = SSHSecurityPolicy(
            name="Default",
            description="default",
            require_host_key_verification=True,
            created_by=admin_user.id,
        )
        db.add(p)
        db.flush()
    return p


@pytest.fixture
def credential(db):
    c = Credential(
        name="pra424-cred",
        auth_method="password",
        username="praxis",
        vault_path="secret/praxis/pra424-cred",
        sudo_method="nopasswd",
    )
    db.add(c)
    db.flush()
    return c


def _checks(*pairs):
    return [
        schemas.serialize_check(check, status, reason)
        for check, status, reason in pairs
    ]


def _unmapped_result():
    """A host that verifies cleanly but reports a distribution nothing carries."""
    return preflight.PreflightResult(
        checks=_checks(
            (schemas.CHECK_ADDRESS, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (schemas.CHECK_NETWORK, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (schemas.CHECK_HOST_IDENTITY, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (
                schemas.CHECK_AUTHENTICATION,
                schemas.STATUS_PASS,
                schemas.REASON_VERIFIED,
            ),
            (schemas.CHECK_COMMAND, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (schemas.CHECK_SUDO, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
        ),
        offered_host_key=preflight.OfferedHostKey(
            key_type="ssh-ed25519",
            public_key="AAAAC3NzaC1lZDI1NTE5AAAAIpra424",
            fingerprint="a" * 64,
        ),
        identity={"hostname": "pra424-01", "fqdn": "pra424-01.test", "arch": "x86_64"},
        os_release={"ID": "voidlinux", "NAME": "Void Linux", "VERSION_ID": "rolling"},
        resolved_ip="10.74.0.11",
    )


@pytest.fixture
def stub_preflight(monkeypatch):
    state = {"result": _unmapped_result()}

    def _run(db, target, *, collect_identity=True):
        return state["result"]

    monkeypatch.setattr(preflight, "run_preflight", _run)
    return state


def _open_draft(client):
    res = client.post("/onboarding/drafts")
    assert res.status_code == 201, res.text
    return res.json()["draft"]


def _reach_discover_by_skipping(client, credential, *, address="10.74.0.11"):
    """Connect, authenticate, then decline verification. Nothing is read."""
    draft = _open_draft(client)
    did = draft["id"]

    res = client.put(
        f"/onboarding/drafts/{did}/connect",
        json={"address": address, "ssh_port": 22, "hostname": "pra424-01"},
    )
    assert res.status_code == 200, res.text

    res = client.put(
        f"/onboarding/drafts/{did}/authenticate",
        json={"credential_id": credential.id},
    )
    assert res.status_code == 200, res.text

    res = client.post(
        f"/onboarding/drafts/{did}/skip-verification", json={"acknowledged": True}
    )
    assert res.status_code == 200, res.text
    body = res.json()["draft"]
    assert body["discovery"] is None
    assert body["current_step"] == "discover"
    return did


def _discover_unmapped(client, credential, *, address="10.74.0.11"):
    """Walk to Discover against a host whose distribution nothing carries."""
    did = _open_draft(client)["id"]

    res = client.put(
        f"/onboarding/drafts/{did}/connect",
        json={"address": address, "ssh_port": 22, "hostname": "pra424-01"},
    )
    assert res.status_code == 200, res.text
    res = client.put(
        f"/onboarding/drafts/{did}/authenticate",
        json={"credential_id": credential.id},
    )
    assert res.status_code == 200, res.text
    res = client.post(f"/onboarding/drafts/{did}/verify")
    assert res.status_code == 200, res.text
    fingerprint = res.json()["draft"]["host_key"]["fingerprint"]
    res = client.put(
        f"/onboarding/drafts/{did}/host-key",
        json={"accept": True, "fingerprint": fingerprint},
    )
    assert res.status_code == 200, res.text

    res = client.post(f"/onboarding/drafts/{did}/discover")
    assert res.status_code == 200, res.text
    discovery = res.json()["draft"]["discovery"]
    assert discovery["support_mapping"] == schemas.SUPPORT_MAPPING_UNKNOWN
    assert discovery["distro_id"] is None
    assert res.json()["draft"]["current_step"] == "discover"
    return did


class TestSkippedVerification:
    """The operator's own answer is the only evidence there is."""

    def test_naming_the_distribution_is_accepted_and_moves_the_setup_on(
        self, authed_client, db, credential, distro, default_policy
    ):
        did = _reach_discover_by_skipping(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": False},
        )
        assert res.status_code == 200, res.text

        draft = res.json()["draft"]
        assert draft["current_step"] == "organize"
        discovery = draft["discovery"]
        assert discovery["distro_id"] == distro.id
        assert discovery["support_mapping"] == schemas.SUPPORT_MAPPING_DECLARED
        assert discovery["confirmed_unknown"] is False
        # Recorded as the operator's declaration, not as something read from
        # the host: nothing was.
        assert discovery["distro_name"] == "Debian"
        assert discovery["distro_version"] == "13"
        assert discovery["effective_hostname"] is None
        assert discovery["architecture"] is None
        assert discovery["package_family"] is None

    def test_the_setup_finishes_and_registers_the_declared_distribution(
        self, authed_client, db, credential, group, distro, default_policy
    ):
        did = _reach_discover_by_skipping(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": False},
        )
        assert res.status_code == 200, res.text

        res = authed_client.put(
            f"/onboarding/drafts/{did}/organize",
            json={"group_id": group.id, "environment": "Production", "tags": []},
        )
        assert res.status_code == 200, res.text

        res = authed_client.post(f"/onboarding/drafts/{did}/confirm")
        assert res.status_code == 200, res.text
        confirmed = res.json()["draft"]

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={
                "finalize_token": confirmed["finalize_token"],
                "state_version": confirmed["state_version"],
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["created"] is True
        assert body["verification_skipped"] is True
        # Unverified, so the host is registered but not reported Active.
        assert body["status"] == "Inactive"

        system = db.query(System).filter_by(id=body["system_id"]).one()
        assert system.distro_id == distro.id
        assert system.os_version == "13"

    def test_continuing_without_naming_anything_is_refused(
        self, authed_client, db, credential, default_policy
    ):
        did = _reach_discover_by_skipping(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": None, "confirmed_unknown": True},
        )
        assert res.status_code == 400, res.text
        detail = res.json()["detail"]
        assert detail["code"] == "distro_unsupported"
        assert "supported release" in detail["message"]

    def test_an_unknown_distribution_id_is_refused(
        self, authed_client, db, credential, default_policy
    ):
        did = _reach_discover_by_skipping(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": 987654, "confirmed_unknown": False},
        )
        assert res.status_code == 400, res.text
        assert res.json()["detail"]["code"] == "reference_missing"


class TestUnmappedDiscovery:
    def test_choosing_a_distribution_is_not_recorded_as_an_unmapped_host(
        self, authed_client, db, credential, distro, default_policy, stub_preflight
    ):
        did = _discover_unmapped(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": False},
        )
        assert res.status_code == 200, res.text
        confirmed = res.json()["draft"]["discovery"]
        assert confirmed["distro_id"] == distro.id
        assert confirmed["confirmed_unknown"] is False
        # What the host actually reported survives the operator's mapping.
        assert confirmed["distro_name"] == "Void Linux"
        assert confirmed["support_mapping"] == schemas.SUPPORT_MAPPING_UNKNOWN

    def test_an_unmapped_host_is_refused_here_rather_than_at_finish(
        self, authed_client, db, credential, group, default_policy, stub_preflight
    ):
        """The refusal lands where the operator can still act on it, and it
        names what the host reported so they know which distribution is
        unsupported."""
        did = _discover_unmapped(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": None, "confirmed_unknown": True},
        )
        assert res.status_code == 400, res.text
        detail = res.json()["detail"]
        assert detail["code"] == "distro_unsupported"
        assert "Void Linux rolling" in detail["message"]

        # The draft did not move on, and nothing about it was rewritten.
        res = authed_client.get(f"/onboarding/drafts/{did}")
        assert res.status_code == 200, res.text
        draft = res.json()["draft"]
        assert draft["current_step"] == "discover"
        assert draft["discovery"]["distro_id"] is None
        assert draft["discovery"]["confirmed_unknown"] is False

    def test_an_acknowledgement_alongside_a_choice_still_binds_the_choice(
        self, authed_client, db, credential, distro, default_policy, stub_preflight
    ):
        """A client still sending the old acknowledgement is not punished for
        it when the operator did pick a supported release."""
        did = _discover_unmapped(authed_client, credential)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": True},
        )
        assert res.status_code == 200, res.text
        confirmed = res.json()["draft"]["discovery"]
        assert confirmed["distro_id"] == distro.id
        assert confirmed["confirmed_unknown"] is False
