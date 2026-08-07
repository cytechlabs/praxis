"""PRA-159 #5: GET /content-profiles/{id}/subscribers route tests.

Subscribers (effective hosts) is distinct from /subscriptions
(every binding row pointing AT the profile, including conflicts).
The route walks every System through the resolver and returns the
subset whose effective profile lands on this profile.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    ContentProfile,
    Credential,
    Group,
    GroupContentProfileSubscription,
    HostContentProfileSubscription,
    System,
)


@pytest.fixture
def fleet(db, seed_distro):
    """Two profiles, three hosts:

    * alice — direct → prod (resolved as prod)
    * bob — group → stage (resolved as stage)
    * carol — direct → prod AND direct → stage (CONFLICT)
    """
    g = Group(name="subs-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="subs-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()

    hosts = {}
    for hostname, ip in (
        ("alice", "10.90.0.1"),
        ("bob", "10.90.0.2"),
        ("carol", "10.90.0.3"),
    ):
        h = System(
            hostname=f"{hostname}.example.com",
            ip_address=ip,
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=g.id,
            credentials_id=cred.id,
        )
        db.add(h)
        db.flush()
        hosts[hostname] = h

    prod = ContentProfile(slug="prod", display_name="Prod", package_family="deb")
    stage = ContentProfile(slug="stage", display_name="Stage", package_family="deb")
    db.add_all([prod, stage])
    db.flush()

    # alice — direct → prod
    db.add(
        HostContentProfileSubscription(host_id=hosts["alice"].id, profile_id=prod.id)
    )
    # bob — group → stage
    db.add(GroupContentProfileSubscription(group_id=g.id, profile_id=stage.id))
    # carol — direct conflict (both prod and stage)
    db.add(
        HostContentProfileSubscription(host_id=hosts["carol"].id, profile_id=prod.id)
    )
    db.add(
        HostContentProfileSubscription(host_id=hosts["carol"].id, profile_id=stage.id)
    )
    db.commit()
    return {"hosts": hosts, "prod": prod, "stage": stage}


def test_subscribers_returns_only_resolved_hosts_for_prod(authed_client, fleet):
    res = authed_client.get(f"/content-profiles/{fleet['prod'].id}/subscribers")
    assert res.status_code == 200
    body = res.json()
    hostnames = sorted(s["hostname"] for s in body)
    # alice resolves to prod via direct.
    # bob is on stage (group tier wins because direct is empty for him).
    # carol is in conflict — does NOT count as a subscriber.
    assert hostnames == ["alice.example.com"]
    assert body[0]["via_kind"] == "direct"


def test_subscribers_returns_group_via_kind(authed_client, fleet):
    res = authed_client.get(f"/content-profiles/{fleet['stage'].id}/subscribers")
    assert res.status_code == 200
    hostnames = sorted(s["hostname"] for s in res.json())
    assert hostnames == ["bob.example.com"]
    bob = res.json()[0]
    assert bob["via_kind"] == "group"
    assert bob["via_label"] == "subs-grp"


def test_subscribers_excludes_conflict_hosts(authed_client, fleet):
    """carol has direct subscriptions to both prod and stage —
    conflict at the direct tier means she has NO effective profile,
    so neither subscribers list includes her."""
    for profile_id in (fleet["prod"].id, fleet["stage"].id):
        body = authed_client.get(f"/content-profiles/{profile_id}/subscribers").json()
        assert "carol.example.com" not in {s["hostname"] for s in body}


def test_subscribers_404_unknown_profile(authed_client):
    assert authed_client.get("/content-profiles/999999/subscribers").status_code == 404
