"""PRA-159 #5: validate_rule_against_db tests.

DB-backed value validation runs after the DB-free ``validate_rule``;
today only profile.subscribed_to slugs are checked, but the helper
extends to any future DB-backed enum.
"""

from __future__ import annotations

import pytest

from app.db.models import ContentProfile
from app.services.smart_group_service import (
    RuleValidationError,
    validate_rule_against_db,
)


@pytest.fixture
def two_profiles(db):
    p1 = ContentProfile(slug="prod", display_name="Prod", package_family="deb")
    p2 = ContentProfile(slug="stage", display_name="Stage", package_family="deb")
    db.add_all([p1, p2])
    db.commit()
    return [p1, p2]


def test_validate_rule_against_db_accepts_known_slugs(db, two_profiles):
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["prod", "stage"],
    }
    validate_rule_against_db(rule, db)  # no raise


def test_validate_rule_against_db_rejects_typo(db, two_profiles):
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["prod", "staage"],  # typo
    }
    with pytest.raises(RuleValidationError, match="staage"):
        validate_rule_against_db(rule, db)


def test_validate_rule_against_db_case_insensitive(db, two_profiles):
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["PROD"],
    }
    validate_rule_against_db(rule, db)  # accepted


def test_validate_rule_against_db_filters_soft_deleted(db, two_profiles):
    """A soft-deleted profile is not a legal slug — referencing it
    should fail just like a typo would, so operators don't silently
    bind to dormant profiles."""
    from datetime import datetime

    db.query(ContentProfile).filter(ContentProfile.slug == "stage").update(
        {"deleted_at": datetime.utcnow()}
    )
    db.commit()
    rule = {
        "field": "profile.subscribed_to",
        "op": "in",
        "value": ["stage"],
    }
    with pytest.raises(RuleValidationError, match="stage"):
        validate_rule_against_db(rule, db)


def test_validate_rule_against_db_rejects_in_not_in_arms_equally(db, two_profiles):
    rule = {
        "field": "profile.subscribed_to",
        "op": "not_in",
        "value": ["nope"],
    }
    with pytest.raises(RuleValidationError, match="nope"):
        validate_rule_against_db(rule, db)


def test_validate_rule_against_db_walks_nested_groups(db, two_profiles):
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {
                "op": "or",
                "rules": [
                    {
                        "field": "profile.subscribed_to",
                        "op": "in",
                        "value": ["prod", "ghost"],
                    }
                ],
            },
        ],
    }
    with pytest.raises(RuleValidationError, match="ghost"):
        validate_rule_against_db(rule, db)


def test_validate_rule_against_db_skips_when_no_profile_predicate(db):
    """No DB roundtrip when the rule doesn't reference profile.*."""
    rule = {"field": "hostname", "op": "eq", "value": "x"}
    validate_rule_against_db(rule, db)  # no raise, no query needed
