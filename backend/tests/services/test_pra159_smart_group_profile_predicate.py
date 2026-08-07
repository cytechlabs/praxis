"""PRA-159 #4: profile.* smart-group predicate tests.

Covers:
  * profile.subscribed_to in / not_in (case-insensitive)
  * profile.pinned eq true / false
  * Null-FALSE rule for both predicates (no_profile / conflict
    hosts evaluate FALSE on every arm)
  * compute_profile_index handles all three resolution states
  * rule_references_profile fast-path + parse
"""

from __future__ import annotations

import json

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    HostContentProfileSubscription,
    MirrorRepo,
    MirrorSyncRun,
    System,
)
from app.services.smart_group_service import (
    PROFILE_FIELDS,
    compute_profile_index,
    evaluate,
    rule_references_profile,
    validate_rule,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fleet(db, seed_distro):
    """Three hosts:

    * ``alice`` — direct binding to profile ``prod`` (no pin).
    * ``bob`` — direct binding to profile ``stage`` (with pin).
    * ``carol`` — no binding (no_profile).
    """
    g = Group(name="profile-pred-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="profile-pred-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()

    hosts = {}
    for hostname, ip in (
        ("alice", "10.80.0.1"),
        ("bob", "10.80.0.2"),
        ("carol", "10.80.0.3"),
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

    mirror = MirrorRepo(
        slug="profile-pred-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.flush()

    # An ok run so we can pin a channel-repo to it.
    pinned_run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=__import__("datetime").datetime.utcnow(),
        finished_at=__import__("datetime").datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256="a" * 64,
        manifest_path="/tmp/profile-pred-run.manifest.json",
        byte_count=1,
        package_count=1,
    )
    db.add(pinned_run)
    db.flush()

    # Two profiles, one pinned, one not.
    prod_chan = ContentChannel(
        slug="prod-chan", display_name="prod", package_family="deb"
    )
    stage_chan = ContentChannel(
        slug="stage-chan", display_name="stage", package_family="deb"
    )
    db.add_all([prod_chan, stage_chan])
    db.flush()
    db.add(ContentChannelRepo(channel_id=prod_chan.id, mirror_id=mirror.id))
    db.add(
        ContentChannelRepo(
            channel_id=stage_chan.id,
            mirror_id=mirror.id,
            suite_override="jammy-stage",
            pinned_run_id=pinned_run.id,
        )
    )

    prod = ContentProfile(slug="prod", display_name="Prod", package_family="deb")
    stage = ContentProfile(slug="stage", display_name="Stage", package_family="deb")
    db.add_all([prod, stage])
    db.flush()
    db.add(ContentProfileChannel(profile_id=prod.id, channel_id=prod_chan.id))
    db.add(ContentProfileChannel(profile_id=stage.id, channel_id=stage_chan.id))

    db.add(
        HostContentProfileSubscription(host_id=hosts["alice"].id, profile_id=prod.id)
    )
    db.add(HostContentProfileSubscription(host_id=hosts["bob"].id, profile_id=stage.id))
    # carol → no subscription
    db.commit()
    return {"hosts": hosts, "prod": prod, "stage": stage, "mirror": mirror}


# ---------------------------------------------------------------------------
# compute_profile_index
# ---------------------------------------------------------------------------


def test_compute_profile_index_three_states(db, fleet):
    idx = compute_profile_index(db)
    h = fleet["hosts"]
    assert idx[h["alice"].id].effective_slug == "prod"
    assert idx[h["alice"].id].has_pinned_channel is False
    assert idx[h["bob"].id].effective_slug == "stage"
    assert idx[h["bob"].id].has_pinned_channel is True
    assert idx[h["carol"].id].effective_slug is None
    assert idx[h["carol"].id].has_pinned_channel is False


# ---------------------------------------------------------------------------
# profile.subscribed_to
# ---------------------------------------------------------------------------


def test_profile_subscribed_to_in_matches(db, fleet):
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["prod"],
    }
    matched = evaluate(rule, db)
    h = fleet["hosts"]
    assert h["alice"].id in matched
    assert h["bob"].id not in matched
    assert h["carol"].id not in matched


def test_profile_subscribed_to_in_case_insensitive(db, fleet):
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["PROD"],
    }
    matched = evaluate(rule, db)
    assert fleet["hosts"]["alice"].id in matched


def test_profile_subscribed_to_not_in_excludes_unbound(db, fleet):
    """null-FALSE rule (PRA-159 #4 lock): hosts in no_profile do NOT
    match the negative arm — facts.* style, not lifecycle.* style."""
    rule = {
        "field": "profile.subscribed_to",
        "op": "not_in",
        "value": ["prod"],
    }
    matched = evaluate(rule, db)
    h = fleet["hosts"]
    # bob has stage, which is not in [prod] → matches not_in.
    assert h["bob"].id in matched
    # alice has prod → excluded.
    assert h["alice"].id not in matched
    # carol has no profile → null-FALSE, excluded from negative arm.
    assert h["carol"].id not in matched


# ---------------------------------------------------------------------------
# profile.pinned
# ---------------------------------------------------------------------------


def test_profile_pinned_eq_true(db, fleet):
    rule = {"field": "profile.pinned", "op": "eq", "value": True}
    matched = evaluate(rule, db)
    h = fleet["hosts"]
    assert h["bob"].id in matched
    assert h["alice"].id not in matched
    assert h["carol"].id not in matched


def test_profile_pinned_eq_false_excludes_unbound(db, fleet):
    """null-FALSE: an unbound host doesn't match eq=false either —
    same shape as facts.reboot_required."""
    rule = {"field": "profile.pinned", "op": "eq", "value": False}
    matched = evaluate(rule, db)
    h = fleet["hosts"]
    assert h["alice"].id in matched
    assert h["bob"].id not in matched
    assert h["carol"].id not in matched


# ---------------------------------------------------------------------------
# rule_references_profile fast-path
# ---------------------------------------------------------------------------


def test_rule_references_profile_substring_fast_path():
    # Substring missing → False without parsing.
    assert (
        rule_references_profile('{"field":"hostname","op":"eq","value":"x"}') is False
    )


def test_rule_references_profile_parse_path():
    body = {
        "op": "and",
        "rules": [
            {"field": "profile.subscribed_to", "op": "in", "value": ["x"]},
        ],
    }
    assert rule_references_profile(body) is True
    assert rule_references_profile(json.dumps(body)) is True


def test_rule_references_profile_substring_collision_does_not_false_positive():
    """A rule whose VALUE contains the literal "profile." but doesn't
    reference a profile.* field must return False after parsing."""
    body = {
        "field": "hostname",
        "op": "eq",
        "value": "profile.example.com",
    }
    assert rule_references_profile(body) is False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_rule_accepts_profile_predicates():
    validate_rule({"field": "profile.subscribed_to", "op": "in", "value": ["prod"]})
    validate_rule({"field": "profile.pinned", "op": "eq", "value": True})


def test_validate_rule_rejects_bad_profile_op():
    from app.services.smart_group_service import RuleValidationError

    with pytest.raises(RuleValidationError):
        validate_rule({"field": "profile.subscribed_to", "op": "eq", "value": ["x"]})
    with pytest.raises(RuleValidationError):
        validate_rule({"field": "profile.pinned", "op": "in", "value": [True]})


def test_profile_fields_set_locked():
    assert PROFILE_FIELDS == {"profile.subscribed_to", "profile.pinned"}


# ---------------------------------------------------------------------------
# Staleness gap fix
# ---------------------------------------------------------------------------


def test_smart_group_membership_change_propagates_to_profile_predicate(db, fleet):
    """When a smart group bound to a profile gains a member via
    ``recompute_membership``, smart groups filtering on
    ``profile.subscribed_to`` for that profile must re-evaluate so
    the new member appears in their materialised membership without
    requiring a content-profile mutation to trigger a recompute.
    """
    from app.db.models import (
        SmartGroup,
        SmartGroupContentProfileSubscription,
        SmartGroupMembership,
    )
    from app.services.smart_group_service import recompute_membership

    h = fleet["hosts"]
    # carol currently has no profile (no_profile state).
    # Build a smart group whose rule will match carol:
    #   hostname eq "carol.example.com"
    binder = SmartGroup(
        name="binder-sg",
        rule_json=json.dumps(
            {"field": "hostname", "op": "eq", "value": "carol.example.com"}
        ),
    )
    db.add(binder)
    db.flush()
    # Bind it to the prod profile so when carol joins, her effective
    # profile becomes "prod".
    db.add(
        SmartGroupContentProfileSubscription(
            smart_group_id=binder.id, profile_id=fleet["prod"].id
        )
    )
    db.commit()

    # A second smart group filters on profile.subscribed_to in [prod].
    filter_sg = SmartGroup(
        name="prod-filter-sg",
        rule_json=json.dumps(
            {"field": "profile.subscribed_to", "op": "in", "value": ["prod"]}
        ),
    )
    db.add(filter_sg)
    db.commit()

    # Initial state: filter_sg should already include alice (direct
    # binding to prod) but NOT carol (no_profile).
    recompute_membership(db, filter_sg.id)
    members_before = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == filter_sg.id
        )
    }
    assert h["alice"].id in members_before
    assert h["carol"].id not in members_before

    # Now recompute the binder smart group — it should pick up carol.
    # The post-membership-change follow-on MUST trigger
    # recompute_profile_groups, which re-runs filter_sg and
    # discovers carol's new effective profile is "prod".
    recompute_membership(db, binder.id)

    members_after = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == filter_sg.id
        )
    }
    assert h["carol"].id in members_after, (
        "filter_sg should pick up carol after binder_sg gained her as "
        "a member — the membership-staleness gap"
    )


def test_recompute_profile_groups_resweeps_when_binder_changes_mid_sweep(db, fleet):
    """Order-dependent staleness fix.

    ``recompute_profile_groups`` only iterates groups whose rules
    reference ``profile.*``, so the staleness scenario specifically
    requires the binder to ALSO be a profile.*-using group.

    Construction:
      * ``binder_sg`` — rule
        ``profile.subscribed_to in [stage]``, also bound to
        ``prod`` via SmartGroupContentProfileSubscription. Pre-seeded
        with carol in ``smart_group_memberships`` (STALE — carol's
        effective profile is no_profile, so she shouldn't actually
        match the rule). The pre-seed makes carol resolve to
        ``prod`` on the first index build (smart-group tier picks
        her up from the cached membership).
      * ``filter_sg`` — rule ``profile.subscribed_to in [prod]``.
        Inserted first so SmartGroup.id ordering puts it earlier in
        the sweep.

    First-pass behaviour:
      * filter_sg evaluated with index — carol's effective=prod
        (from binder_sg's stale cached membership). filter_sg ADDS
        carol.
      * binder_sg evaluated with same index. Its rule
        ``profile.subscribed_to in [stage]`` doesn't match carol
        (effective=prod) → DROPS carol. binder_sg is a profile
        binder → membership change sets the dirty flag.

    Without the resweep, filter_sg would still hold carol — stale.
    With the resweep:
      * Pass 2: filter_sg re-evaluated; index now resolves carol to
        no_profile (binder_sg no longer holds her). filter_sg DROPS
        carol.
      * Pass 2: binder_sg unchanged → dirty flag stays False → loop
        exits.
    """
    from app.db.models import (
        SmartGroup,
        SmartGroupContentProfileSubscription,
        SmartGroupMembership,
    )
    from app.services.smart_group_service import (
        compute_profile_index,
        recompute_profile_groups,
    )

    h = fleet["hosts"]

    # Insert the filter group FIRST so it's processed before the
    # binder in a single sweep iteration.
    filter_sg = SmartGroup(
        name="a-prod-filter",
        rule_json=json.dumps(
            {"field": "profile.subscribed_to", "op": "in", "value": ["prod"]}
        ),
    )
    db.add(filter_sg)
    db.flush()

    binder_sg = SmartGroup(
        name="z-stage-binder",
        rule_json=json.dumps(
            {"field": "profile.subscribed_to", "op": "in", "value": ["stage"]}
        ),
    )
    db.add(binder_sg)
    db.flush()
    db.add(
        SmartGroupContentProfileSubscription(
            smart_group_id=binder_sg.id, profile_id=fleet["prod"].id
        )
    )
    # Pre-seed STALE membership: carol shouldn't actually match
    # binder_sg's rule, but the cache says she does. The cached row
    # gives her an effective profile of "prod" via the smart-group
    # tier on the first index build.
    db.add(SmartGroupMembership(smart_group_id=binder_sg.id, system_id=h["carol"].id))
    db.commit()

    # Confirm the pre-seed produces carol→prod in the first index
    # so the test premise holds.
    pre = compute_profile_index(db)
    assert pre[h["carol"].id].effective_slug == "prod"

    recompute_profile_groups(db)

    final_filter_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == filter_sg.id
        )
    }
    assert h["carol"].id not in final_filter_members, (
        "carol should NOT remain in filter_sg after the re-sweep — "
        "binder_sg's stale membership was cleared in pass 1, and "
        "pass 2 should re-evaluate filter_sg against the new index."
    )
    # alice's direct binding pre-existing.
    assert h["alice"].id in final_filter_members


def test_recompute_profile_groups_re_entry_guarded(db, fleet):
    """A profile.*-using smart group that ALSO has a
    SmartGroupContentProfileSubscription of its own must not loop:
    the module-level recursion guard short-circuits the follow-on
    when we're already inside a profile recompute sweep.
    """
    from app.db.models import SmartGroup, SmartGroupContentProfileSubscription
    from app.services.smart_group_service import (
        _RECOMPUTING_PROFILE_GROUPS,
        recompute_profile_groups,
    )

    # Confirm the flag is False at rest.
    assert _RECOMPUTING_PROFILE_GROUPS is False

    sg = SmartGroup(
        name="profile-and-binder",
        rule_json=json.dumps(
            {"field": "profile.subscribed_to", "op": "in", "value": ["prod"]}
        ),
    )
    db.add(sg)
    db.flush()
    db.add(
        SmartGroupContentProfileSubscription(
            smart_group_id=sg.id, profile_id=fleet["prod"].id
        )
    )
    db.commit()

    # Top-level call should complete without RecursionError.
    touched = recompute_profile_groups(db)
    assert touched >= 1

    # And the flag must be cleared back to False on exit (no leaks
    # across calls).
    from app.services import smart_group_service

    assert smart_group_service._RECOMPUTING_PROFILE_GROUPS is False
