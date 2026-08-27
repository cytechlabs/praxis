"""PRA-414: the guided onboarding HTTP surface.

Walks the seven steps end to end, then pins the boundaries that matter: who may
start a setup, who may resume one, what a stale or replayed confirmation does,
and the guarantee that nothing permanent exists until Finish succeeds.

Preflight is substituted, because these tests are about the wizard contract
rather than about SSH. The preflight service has its own tests, and the real
host matrix is exercised separately against disposable targets.
"""

from datetime import date, datetime, timedelta

import pytest

from app.api.schemas import onboarding as schemas
from app.db.models import Credential, Distro, Group, System, User
from app.db.onboarding_models import DRAFT_STATUS_CANCELED, SystemOnboardingDraft
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight

# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


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
    d = db.query(Distro).filter_by(name="Debian", version="12").first()
    if d is None:
        d = Distro(
            name="Debian",
            version="12",
            release_date=date(2023, 6, 10),
            end_of_life_date=date(2028, 6, 10),
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
        name="wizard-cred",
        auth_method="password",
        username="praxis",
        vault_path="secret/praxis/wizard-cred",
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


def _verified_result(**overrides):
    result = preflight.PreflightResult(
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
            public_key="AAAAC3NzaC1lZDI1NTE5AAAAIwizard",
            fingerprint="f" * 64,
        ),
        identity={"hostname": "wizard-01", "fqdn": "wizard-01.test", "arch": "x86_64"},
        os_release={"ID": "debian", "NAME": "Debian", "VERSION_ID": "12"},
        resolved_ip="10.70.0.10",
    )
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


def _unknown_key_result():
    return preflight.PreflightResult(
        checks=_checks(
            (schemas.CHECK_ADDRESS, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (schemas.CHECK_NETWORK, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
            (
                schemas.CHECK_HOST_IDENTITY,
                schemas.STATUS_FAIL,
                schemas.REASON_HOST_KEY_UNKNOWN,
            ),
        ),
        offered_host_key=preflight.OfferedHostKey(
            key_type="ssh-ed25519",
            public_key="AAAAC3NzaC1lZDI1NTE5AAAAIwizard",
            fingerprint="f" * 64,
        ),
        resolved_ip="10.70.0.10",
    )


@pytest.fixture
def stub_preflight(monkeypatch):
    """Drive preflight from the test rather than from a real host."""
    state = {"result": _verified_result(), "calls": 0}

    def _run(db, target, *, collect_identity=True):
        state["calls"] += 1
        state["last_target"] = target
        result = state["result"]
        return result() if callable(result) else result

    monkeypatch.setattr(preflight, "run_preflight", _run)
    return state


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _open_draft(client):
    res = client.post("/onboarding/drafts")
    assert res.status_code == 201, res.text
    return res.json()["draft"]


def _walk_to_confirm(client, credential, group, *, address="10.70.0.10", port=22):
    """Connect -> authenticate -> verify -> trust key -> discover -> organize."""
    draft = _open_draft(client)
    did = draft["id"]

    res = client.put(
        f"/onboarding/drafts/{did}/connect",
        json={"address": address, "ssh_port": port, "hostname": "wizard-01"},
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

    res = client.put(
        f"/onboarding/drafts/{did}/organize",
        json={
            "group_id": group.id,
            "environment": "Production",
            "description": "wizard host",
            "tags": ["wizard"],
        },
    )
    assert res.status_code == 200, res.text

    res = client.post(f"/onboarding/drafts/{did}/confirm")
    assert res.status_code == 200, res.text
    return did, res.json()


# --------------------------------------------------------------------------- #
# Authorization                                                                #
# --------------------------------------------------------------------------- #


class TestAuthorization:
    def test_an_auditor_may_not_start_a_setup(self, client, db, auditor_user):
        from app.core.auth import create_access_token

        token = create_access_token(data={"sub": auditor_user.username})
        res = client.post(
            "/onboarding/drafts", headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 403

    def test_capabilities_are_reported_before_any_form(self, authed_client):
        res = authed_client.get("/onboarding/capabilities")
        assert res.status_code == 200, res.text
        caps = res.json()["capabilities"]
        assert caps["can_onboard"] is True
        assert caps["can_create_credential"] is True
        assert caps["scope"] == "tenant_wide"

    def test_a_scoped_maintainer_may_not_create_credentials(
        self, client, db, seed_roles
    ):
        """Credential creation is tenant-wide only, and the wizard says so up
        front rather than failing at submit time."""
        from app.core.auth import create_access_token

        user = User(
            username="scopedmaint",
            email="scoped@example.com",
            hashed_password="x",
            is_active=True,
        )
        user.roles.append(seed_roles["maintainer"])
        db.add(user)
        db.flush()

        token = create_access_token(data={"sub": user.username})
        res = client.get(
            "/onboarding/capabilities", headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200, res.text
        caps = res.json()["capabilities"]
        assert caps["scope"] == "scoped"
        assert caps["can_create_credential"] is False
        assert caps["can_onboard"] is True


class TestOwnership:
    def test_another_operator_cannot_resume_a_draft(
        self, authed_client, client, db, seed_roles
    ):
        from app.core.auth import create_access_token

        draft = _open_draft(authed_client)

        other = User(
            username="secondadmin",
            email="second@example.com",
            hashed_password="x",
            is_active=True,
        )
        other.roles.append(seed_roles["admin"])
        db.add(other)
        db.flush()
        token = create_access_token(data={"sub": other.username})

        res = client.get(
            f"/onboarding/drafts/{draft['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 404


# --------------------------------------------------------------------------- #
# The wizard                                                                   #
# --------------------------------------------------------------------------- #


class TestVerifyStep:
    def test_an_unknown_host_key_is_reported_for_review_not_trusted(
        self, authed_client, db, credential, default_policy, stub_preflight
    ):
        stub_preflight["result"] = _unknown_key_result()
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )

        res = authed_client.post(f"/onboarding/drafts/{did}/verify")
        assert res.status_code == 200, res.text
        body = res.json()["draft"]

        assert body["verification"]["verified"] is False
        assert body["host_key"]["fingerprint"] == "f" * 64
        # Captured for review, but explicitly not trusted yet.
        assert body["host_key"]["decision"] == "pending"

    def test_verification_returns_structured_codes_not_transport_text(
        self, authed_client, db, credential, default_policy, stub_preflight
    ):
        stub_preflight["result"] = preflight.PreflightResult(
            checks=_checks(
                (schemas.CHECK_ADDRESS, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
                (
                    schemas.CHECK_NETWORK,
                    schemas.STATUS_FAIL,
                    schemas.REASON_CONNECTION_TIMEOUT,
                ),
            )
        )
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.99", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )

        res = authed_client.post(f"/onboarding/drafts/{did}/verify")
        assert res.status_code == 200, res.text
        checks = res.json()["draft"]["verification"]["checks"]
        network = [c for c in checks if c["check"] == "network"][0]
        assert network["reason_code"] == "connection_timeout"
        assert (
            network["message"]
            == schemas.REASON_MESSAGES[schemas.REASON_CONNECTION_TIMEOUT]
        )

    def test_approving_a_stale_fingerprint_is_refused(
        self, authed_client, db, credential, default_policy, stub_preflight
    ):
        stub_preflight["result"] = _unknown_key_result()
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        authed_client.post(f"/onboarding/drafts/{did}/verify")

        res = authed_client.put(
            f"/onboarding/drafts/{did}/host-key",
            json={"accept": True, "fingerprint": "b" * 64},
        )
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "host_key_stale"

    def test_changing_the_address_discards_prior_verification(
        self, authed_client, db, credential, default_policy, stub_preflight, group
    ):
        did, _ = _walk_to_confirm(authed_client, credential, group)

        res = authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.55", "ssh_port": 22, "hostname": "wizard-01"},
        )
        assert res.status_code == 200, res.text
        body = res.json()["draft"]
        # A different endpoint is a different host until proven otherwise.
        assert body["verification"] is None
        assert body["discovery"] is None
        assert body["host_key"]["fingerprint"] is None
        assert body["host_key"]["decision"] == "pending"


class TestDiscoverStep:
    def test_discovery_maps_a_known_distribution(
        self, authed_client, db, credential, default_policy, distro, stub_preflight
    ):
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        authed_client.post(f"/onboarding/drafts/{did}/verify")
        res = authed_client.post(f"/onboarding/drafts/{did}/discover")
        assert res.status_code == 200, res.text

        discovery = res.json()["draft"]["discovery"]
        assert discovery["support_mapping"] == "matched"
        assert discovery["distro_id"] == distro.id
        assert discovery["package_family"] == "deb"
        assert discovery["package_manager"] == "apt"
        assert discovery["architecture"] == "x86_64"
        assert discovery["effective_hostname"] == "wizard-01"

    def test_a_host_that_names_itself_differently_still_maps(
        self, authed_client, db, credential, default_policy, distro, stub_preflight
    ):
        """Debian reports NAME="Debian GNU/Linux" while the catalogue carries
        "Debian". An ordinary Debian host must not read as unsupported."""
        stub_preflight["result"] = _verified_result(
            os_release={
                "ID": "debian",
                "NAME": "Debian GNU/Linux",
                "VERSION_ID": "12",
            }
        )
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        authed_client.post(f"/onboarding/drafts/{did}/verify")
        res = authed_client.post(f"/onboarding/drafts/{did}/discover")
        assert res.status_code == 200, res.text
        discovery = res.json()["draft"]["discovery"]
        assert discovery["support_mapping"] == "matched"
        assert discovery["distro_id"] == distro.id

    def test_a_point_release_maps_to_its_major_catalogue_entry(
        self, authed_client, db, credential, default_policy, distro, stub_preflight
    ):
        """A host reporting 12.5 maps to the catalogue's 12."""
        stub_preflight["result"] = _verified_result(
            os_release={
                "ID": "debian",
                "NAME": "Debian GNU/Linux",
                "VERSION_ID": "12.5",
            }
        )
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        authed_client.post(f"/onboarding/drafts/{did}/verify")
        res = authed_client.post(f"/onboarding/drafts/{did}/discover")
        assert res.status_code == 200, res.text
        assert res.json()["draft"]["discovery"]["distro_id"] == distro.id

    def test_an_unmapped_distribution_needs_explicit_confirmation(
        self, authed_client, db, credential, default_policy, distro, stub_preflight
    ):
        stub_preflight["result"] = _verified_result(
            os_release={"ID": "plan9", "NAME": "Plan 9", "VERSION_ID": "4"}
        )
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        authed_client.post(f"/onboarding/drafts/{did}/verify")
        res = authed_client.post(f"/onboarding/drafts/{did}/discover")
        assert res.status_code == 200, res.text
        body = res.json()["draft"]
        assert body["discovery"]["support_mapping"] == "unknown"
        assert body["discovery"]["distro_id"] is None
        # Not advanced past discovery on its own.
        assert body["current_step"] == "discover"

        res = authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": True},
        )
        assert res.status_code == 200, res.text
        assert res.json()["draft"]["current_step"] == "organize"

    def test_discovery_cannot_run_without_a_working_session(
        self, authed_client, db, credential, default_policy, stub_preflight
    ):
        stub_preflight["result"] = preflight.PreflightResult(
            checks=_checks(
                (schemas.CHECK_ADDRESS, schemas.STATUS_PASS, schemas.REASON_VERIFIED),
                (
                    schemas.CHECK_AUTHENTICATION,
                    schemas.STATUS_FAIL,
                    schemas.REASON_AUTHENTICATION_FAILED,
                ),
            )
        )
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={"address": "10.70.0.10", "ssh_port": 22},
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        res = authed_client.post(f"/onboarding/drafts/{did}/discover")
        assert res.status_code == 409
        detail = res.json()["detail"]
        assert detail["code"] == "discovery_unavailable"
        assert detail["reason_code"] == "authentication_failed"


class TestConfirmAndFinish:
    def test_the_full_walk_creates_one_active_host(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        before = db.query(System).count()
        did, confirm = _walk_to_confirm(authed_client, credential, group)

        preview = confirm["preview"]
        assert preview["hostname"] == "wizard-01"
        assert preview["status"] == "Active"
        assert preview["verified"] is True
        assert preview["ssh_security_policy"]["name"] == "Default"
        assert preview["group"]["name"] == "All Systems"
        assert preview["tags"] == ["wizard"]
        # Access Broker is offered as a follow-up, never done implicitly.
        assert any(f["key"] == "access_broker" for f in confirm["follow_ups"])

        token = confirm["draft"]["finalize_token"]
        version = confirm["draft"]["state_version"]

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["created"] is True
        assert body["status"] == "Active"
        assert db.query(System).count() == before + 1

        system = db.query(System).filter_by(id=body["system_id"]).first()
        assert system.description == "wizard host"
        assert str(system.ip_address) == "10.70.0.10"
        assert system.ssh_security_policy_id == default_policy.id

        # The approved key is promoted through the shared host-key writer.
        stored = db.query(SSHHostKey).filter_by(system_id=system.id).first()
        assert stored is not None
        assert stored.verified is True
        assert stored.fingerprint == "f" * 64

    def test_a_replayed_confirmation_is_refused(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        did, confirm = _walk_to_confirm(authed_client, credential, group)
        token = confirm["draft"]["finalize_token"]
        version = confirm["draft"]["state_version"]

        first = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert first.status_code == 200, first.text
        count_after = db.query(System).count()

        # Submitting the same confirmation again returns the same host.
        second = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert second.status_code == 200, second.text
        assert second.json()["created"] is False
        assert second.json()["system_id"] == first.json()["system_id"]
        assert db.query(System).count() == count_after

    def test_a_stale_confirmation_is_refused(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        before = db.query(System).count()
        did, confirm = _walk_to_confirm(authed_client, credential, group)
        token = confirm["draft"]["finalize_token"]
        version = confirm["draft"]["state_version"]

        # The operator edits something after confirming.
        res = authed_client.put(
            f"/onboarding/drafts/{did}/organize",
            json={"description": "changed my mind"},
        )
        assert res.status_code == 200, res.text

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "draft_stale"
        assert db.query(System).count() == before

    def test_finishing_a_canceled_draft_creates_nothing(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        before = db.query(System).count()
        did, confirm = _walk_to_confirm(authed_client, credential, group)
        token = confirm["draft"]["finalize_token"]
        version = confirm["draft"]["state_version"]

        res = authed_client.delete(f"/onboarding/drafts/{did}")
        assert res.status_code == 200, res.text
        assert res.json()["draft"]["status"] == DRAFT_STATUS_CANCELED

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert res.status_code == 409
        assert db.query(System).count() == before

    def test_an_expired_draft_creates_nothing(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        before = db.query(System).count()
        did, confirm = _walk_to_confirm(authed_client, credential, group)
        token = confirm["draft"]["finalize_token"]
        version = confirm["draft"]["state_version"]

        row = db.query(SystemOnboardingDraft).filter_by(public_id=did).first()
        row.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={"finalize_token": token, "state_version": version},
        )
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "draft_expired"
        assert db.query(System).count() == before

    def test_a_duplicate_host_is_refused_at_finish(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        did, confirm = _walk_to_confirm(authed_client, credential, group)
        authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={
                "finalize_token": confirm["draft"]["finalize_token"],
                "state_version": confirm["draft"]["state_version"],
            },
        )
        count_after_first = db.query(System).count()

        did2, confirm2 = _walk_to_confirm(authed_client, credential, group)
        res = authed_client.post(
            f"/onboarding/drafts/{did2}/finish",
            json={
                "finalize_token": confirm2["draft"]["finalize_token"],
                "state_version": confirm2["draft"]["state_version"],
            },
        )
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "duplicate_host"
        assert db.query(System).count() == count_after_first


class TestHostKeyFailureAtFinish:
    """A host-key write failure must not leave a half-added host or a wedged
    setup: nothing is created, the claim is released, and the operator can try
    again."""

    def test_nothing_is_created_and_the_setup_stays_usable(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
        monkeypatch,
    ):
        from app.services import onboarding_draft_service as draft_service

        before = db.query(System).count()
        did, confirm = _walk_to_confirm(authed_client, credential, group)

        def _explode(*_args, **_kwargs):
            raise RuntimeError("host key store unavailable")

        monkeypatch.setattr(draft_service, "persist_verified_host_key", _explode)

        with pytest.raises(RuntimeError):
            authed_client.post(
                f"/onboarding/drafts/{did}/finish",
                json={
                    "finalize_token": confirm["draft"]["finalize_token"],
                    "state_version": confirm["draft"]["state_version"],
                },
            )

        # No host, and no trust row orphaned behind one.
        assert db.query(System).count() == before
        assert db.query(SSHHostKey).count() == 0

        # The test session keeps instances alive across commits, so re-read
        # from the database rather than trusting the identity map.
        db.expire_all()
        row = db.query(SystemOnboardingDraft).filter_by(public_id=did).first()
        # The claim was released, so the setup is not stuck mid-finalization.
        assert row.status == "active"
        assert row.finalizing_since is None
        assert row.finalized_system_id is None


class TestSkippedVerification:
    def test_skipping_produces_an_honest_inactive_host(
        self,
        authed_client,
        db,
        credential,
        default_policy,
        distro,
        group,
        stub_preflight,
    ):
        draft = _open_draft(authed_client)
        did = draft["id"]
        authed_client.put(
            f"/onboarding/drafts/{did}/connect",
            json={
                "address": "10.70.0.77",
                "ssh_port": 22,
                "hostname": "skipped-01",
            },
        )
        authed_client.put(
            f"/onboarding/drafts/{did}/authenticate",
            json={"credential_id": credential.id},
        )
        res = authed_client.post(
            f"/onboarding/drafts/{did}/skip-verification",
            json={"acknowledged": True},
        )
        assert res.status_code == 200, res.text
        assert res.json()["draft"]["verification_skipped"] is True

        authed_client.put(
            f"/onboarding/drafts/{did}/discovery-confirmation",
            json={"distro_id": distro.id, "confirmed_unknown": True},
        )
        # Discovery never ran, so the operator names the distribution directly.
        row = db.query(SystemOnboardingDraft).filter_by(public_id=did).first()
        row.discovery = {"support_mapping": "unknown"}
        row.distro_id = distro.id
        row.connection = dict(row.connection, resolved_ip="10.70.0.77")
        db.commit()

        authed_client.put(
            f"/onboarding/drafts/{did}/organize", json={"group_id": group.id}
        )
        confirm = authed_client.post(f"/onboarding/drafts/{did}/confirm").json()
        assert confirm["preview"]["status"] == "Inactive"
        assert confirm["preview"]["verified"] is False

        res = authed_client.post(
            f"/onboarding/drafts/{did}/finish",
            json={
                "finalize_token": confirm["draft"]["finalize_token"],
                "state_version": confirm["draft"]["state_version"],
            },
        )
        assert res.status_code == 200, res.text
        assert res.json()["status"] == "Inactive"
        assert res.json()["verification_skipped"] is True

    def test_skipping_requires_acknowledgement(self, authed_client, credential):
        draft = _open_draft(authed_client)
        res = authed_client.post(
            f"/onboarding/drafts/{draft['id']}/skip-verification",
            json={"acknowledged": False},
        )
        assert res.status_code == 422


class TestOptionEndpointsDoNotLeakSecretPaths:
    def test_credential_options_omit_the_vault_path(
        self, authed_client, credential, default_policy
    ):
        res = authed_client.get("/onboarding/credential-options")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["credentials"]
        for entry in body["credentials"]:
            assert "vault_path" not in entry
            assert set(entry) == {
                "id",
                "name",
                "username",
                "auth_method",
                "sudo_method",
                "source",
            }
        assert body["default_ssh_security_policy_id"] == default_policy.id

    def test_organization_options_offer_the_real_default_group(
        self, authed_client, group, distro
    ):
        res = authed_client.get("/onboarding/organization-options")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["default_group_id"] == group.id
        assert "Production" in body["environments"]


class TestInputBounds:
    @pytest.mark.parametrize("port", [0, 65536, "22", True])
    def test_an_invalid_port_is_refused(self, authed_client, port):
        draft = _open_draft(authed_client)
        res = authed_client.put(
            f"/onboarding/drafts/{draft['id']}/connect",
            json={"address": "10.70.0.10", "ssh_port": port},
        )
        assert res.status_code == 422

    @pytest.mark.parametrize("address", ["", "-nope", "10.0.0.1/24"])
    def test_an_invalid_address_is_refused(self, authed_client, address):
        draft = _open_draft(authed_client)
        res = authed_client.put(
            f"/onboarding/drafts/{draft['id']}/connect",
            json={"address": address, "ssh_port": 22},
        )
        assert res.status_code == 422

    def test_too_many_tags_are_refused(self, authed_client):
        draft = _open_draft(authed_client)
        res = authed_client.put(
            f"/onboarding/drafts/{draft['id']}/organize",
            json={"tags": [f"t{i}" for i in range(schemas.MAX_TAGS + 1)]},
        )
        assert res.status_code == 422
