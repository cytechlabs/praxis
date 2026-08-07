"""PRA-310: secret redaction for support artifacts."""

from __future__ import annotations

import pytest

from app.core.redaction import redact_text


def test_redacts_vault_tokens():
    # HashiCorp Vault shapes (hvs./hvb./hvr.) AND OpenBao shapes (PRA-311): service
    # `s.<24+>` and batch `b.<long base64>`. OpenBao does not use the `hv*` prefixes.
    for tok in (
        "hvs.CAESIBlSZAeRIkDy",
        "s.abcdefghijklmnopqrstuvwx",  # OpenBao/legacy service token
        "hvb.AAAAAQ",
        "b.AAAAAQKZmV4YW1wbGViYXRjaHRva2VucGF5bG9hZHZhbHVlMDA",  # OpenBao batch token
    ):
        out = redact_text(f"VAULT_TOKEN={tok} rest")
        assert tok not in out


def test_redacts_jwt_license_and_access_tokens():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"
    out = redact_text(f"license {jwt} tail")
    assert jwt not in out
    assert "«redacted-jwt»" in out


def test_redacts_key_value_secrets():
    out = redact_text("password=hunter2 token: abc123 secret_key=zzz")
    assert "hunter2" not in out
    assert "abc123" not in out
    assert "zzz" not in out


def test_redacts_private_key_block():
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA...secret...ZZZZ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    out = redact_text(f"key:\n{pem}\nend")
    assert "secret" not in out
    assert "«redacted-private-key»" in out


def test_redacts_bearer_and_dsn_credentials():
    assert "topsecrettoken" not in redact_text("Authorization: Bearer topsecrettoken")
    dsn = "postgresql://praxis:supersecret@db:5432/praxis"
    out = redact_text(dsn)
    assert "supersecret" not in out
    assert "db:5432/praxis" in out  # non-secret parts preserved


def test_redaction_is_total_and_idempotent():
    assert redact_text(None) is None
    assert redact_text("") == ""
    once = redact_text("token=abc password=def")
    assert redact_text(once) == once


# ------------------------------------------------- compound + quoted key forms
#
# PRA-369: `\b` cannot match a sensitive suffix in a compound key because `_` is a
# regex word character, and the old value matcher only understood double quotes.
# These are the confirmed bypasses plus the surrounding shapes they generalize to.


@pytest.mark.parametrize(
    "line, secret",
    [
        ("agent_token=abcdef123456", "abcdef123456"),
        ("totp_secret=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
        ("my_password=hunter2", "hunter2"),
        ("{'token': 'abc123def'}", "abc123def"),
    ],
)
def test_confirmed_bypasses_are_redacted(line, secret):
    out = redact_text(line)
    assert secret not in out
    assert "«redacted»" in out


@pytest.mark.parametrize(
    "key",
    [
        "agent_token",
        "agent-token",
        "totp_secret",
        "totp-secret",
        "my_password",
        "my-password",
        "db_pwd",
        "broker_api_key",
        "service_client_secret",
        "x_access_token",
        "mirror_signing_private_key",
    ],
)
def test_compound_keys_are_redacted(key):
    out = redact_text(f"{key}=s3cr3tvalue")
    assert "s3cr3tvalue" not in out
    # The compound key itself stays readable; only the value is replaced.
    assert key in out


@pytest.mark.parametrize(
    "line",
    [
        "token=abc123def",
        "token: abc123def",
        "token = abc123def",
        'token="abc123def"',
        "token='abc123def'",
        '"token": "abc123def"',
        "{'token': 'abc123def'}",
        '{"token": "abc123def"}',
        "token => abc123def",
        "TOKEN=abc123def",
        "Token: abc123def",
    ],
)
def test_quoting_and_separator_variants(line):
    out = redact_text(line)
    assert "abc123def" not in out
    assert "«redacted»" in out


def test_quoted_values_with_spaces_and_punctuation():
    out = redact_text('password = "hunter 2, really!" host=db')
    assert "hunter 2, really!" not in out
    # The quoted value is consumed whole, so the following field survives.
    assert "host=db" in out

    out = redact_text("token='a b c' next=keepme")
    assert "a b c" not in out
    assert "next=keepme" in out


def test_neighboring_fields_survive():
    out = redact_text("host=db port=5432 password=pw user=praxis")
    assert "pw" not in out.replace("«redacted»", "")
    assert "host=db" in out
    assert "port=5432" in out
    assert "user=praxis" in out


def test_structural_punctuation_before_and_after_key():
    out = redact_text("(password=pw) [token=tk] {secret=sk}")
    for secret in ("pw", "tk", "sk"):
        assert secret not in out.replace("«redacted»", "")
    # Brackets/braces are not swallowed into the value.
    assert out.count(")") == 1 and out.count("]") == 1 and out.count("}") == 1


def test_container_value_is_left_intact():
    # A value that opens an object is not a scalar secret; redacting it would
    # destroy the structure of a JSON dump.
    out = redact_text('{"token": {"nested": 1}}')
    assert out == '{"token": {"nested": 1}}'


def test_multiline_input_redacts_every_line():
    out = redact_text("line1 token=aaa\nline2 password=bbb\nline3 ok")
    assert "aaa" not in out
    assert "bbb" not in out
    assert "line3 ok" in out
    assert len(out.splitlines()) == 3


def test_compound_and_quoted_forms_are_idempotent():
    text = (
        "agent_token=abcdef123456 totp_secret=JBSWY3DPEHPK3PXP\n"
        "my_password=hunter2 {'token': 'abc123def'}\n"
        'password = "hunter 2" host=db'
    )
    once = redact_text(text)
    assert redact_text(once) == once


# ------------------------------------------------------------- negative cases


@pytest.mark.parametrize(
    "text",
    [
        "The password is stored in Vault.",
        "Rotate the token before the secret expires.",
        "tokenizer=nltk",
        "count=5 hostname=web01",
        "password_reset_requested by admin",
        "See the private key handling docs.",
    ],
)
def test_ordinary_prose_and_non_sensitive_assignments_survive(text):
    assert redact_text(text) == text


@pytest.mark.parametrize("text", ["mypassword=value", "topsecret=value"])
def test_concatenated_keys_without_a_delimiter_are_not_matched(text):
    """Locks the deliberate boundary of the delimiter-aware lookbehind.

    Only compound keys joined by `_` or `-` are covered. A sensitive word fused
    into a longer identifier is left alone, which is the price of not matching
    inside arbitrary words. Widening this is a conscious decision, not a silent
    regex tweak.
    """
    assert redact_text(text) == text


def test_separator_does_not_consume_across_a_newline():
    """Locks the horizontal-whitespace-only separator.

    A key whose value sits on the next line is not redacted, so a dangling
    `password:` at the end of a log line can never swallow the first word of the
    following record. Log text and ``json.dumps(indent=2)`` both keep key and
    value on one line, so the bundle paths are unaffected.
    """
    text = "password:\n  value"
    assert redact_text(text) == text
    # The following line survives intact, which is the property that matters.
    assert redact_text(text).splitlines()[1] == "  value"
