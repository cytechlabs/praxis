"""PRA-310: secret redaction for support artifacts."""

from __future__ import annotations

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
