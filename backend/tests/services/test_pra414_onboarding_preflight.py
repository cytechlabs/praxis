"""PRA-414: preflight verification reports structured codes, never raw text.

The wizard has to explain *why* a host did not connect without ever putting a
transport or library message in front of an operator, in a draft, or in an
audit row. These tests pin the reason-code vocabulary, the derivation of
operator wording from codes alone, the policy reading that must fail closed,
and the credential key formats verification accepts.
"""

from unittest.mock import MagicMock

import paramiko
import pytest

from app.api.schemas import onboarding as schemas
from app.db.models import Credential
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight


class TestReasonCodeVocabulary:
    def test_every_required_code_exists(self):
        required = {
            "address_invalid",
            "network_unreachable",
            "connection_timeout",
            "host_key_unknown",
            "host_key_mismatch",
            "ssh_policy_rejected",
            "authentication_failed",
            "username_missing",
            "key_type_unsupported",
            "command_failed",
            "sudo_password_required",
            "sudo_denied",
            "sudo_unavailable",
            "verified",
        }
        assert required.issubset(set(schemas.REASON_CODES))

    def test_every_code_has_operator_wording(self):
        for code in schemas.REASON_CODES:
            assert schemas.REASON_MESSAGES.get(code)

    def test_wording_comes_from_the_code_not_a_caller(self):
        check = schemas.serialize_check(
            schemas.CHECK_AUTHENTICATION,
            schemas.STATUS_FAIL,
            schemas.REASON_AUTHENTICATION_FAILED,
        )
        assert (
            check["message"]
            == schemas.REASON_MESSAGES[schemas.REASON_AUTHENTICATION_FAILED]
        )

    def test_an_unknown_code_cannot_be_serialized(self):
        with pytest.raises(ValueError):
            schemas.serialize_check(
                schemas.CHECK_SUDO, schemas.STATUS_FAIL, "paramiko_exploded"
            )

    def test_an_unknown_check_cannot_be_serialized(self):
        with pytest.raises(ValueError):
            schemas.serialize_check(
                "arbitrary", schemas.STATUS_FAIL, schemas.REASON_VERIFIED
            )


class TestStoredVerificationCarriesNoTransportText:
    def test_only_codes_booleans_and_timestamps_are_stored(self):
        checks = [
            schemas.serialize_check(
                schemas.CHECK_NETWORK,
                schemas.STATUS_FAIL,
                schemas.REASON_NETWORK_UNREACHABLE,
            )
        ]
        block = schemas.serialize_verification(
            checks, verified=False, completed_at="2026-08-27T00:00:00"
        )
        serialized = repr(block)
        # Nothing resembling a library traceback or socket error survives.
        assert "Traceback" not in serialized
        assert "paramiko" not in serialized.lower()
        for check in block["checks"]:
            assert set(check) <= {"check", "status", "reason_code", "message"}
            assert check["reason_code"] in schemas.REASON_CODES


class TestPolicyReadingFailsClosed:
    def test_no_policy_still_requires_host_key_verification(self):
        assert preflight.policy_requires_host_key_verification(None) is True

    def test_a_policy_with_an_unset_flag_still_verifies(self):
        policy = SSHSecurityPolicy(name="unset", require_host_key_verification=None)
        assert preflight.policy_requires_host_key_verification(policy) is True

    def test_only_an_explicit_false_waives_verification(self):
        waived = SSHSecurityPolicy(name="open", require_host_key_verification=False)
        strict = SSHSecurityPolicy(name="strict", require_host_key_verification=True)
        assert preflight.policy_requires_host_key_verification(waived) is False
        assert preflight.policy_requires_host_key_verification(strict) is True

    def test_allow_lists_translate_into_disabled_algorithms(self):
        policy = SSHSecurityPolicy(
            name="narrow",
            allowed_ciphers="aes256-ctr",
            allowed_macs="hmac-sha2-512",
            allowed_kex="diffie-hellman-group-exchange-sha256",
        )
        disabled = preflight.build_disabled_algorithms(policy)
        assert disabled is not None
        assert "aes256-ctr" not in disabled.get("ciphers", [])
        assert "hmac-sha2-512" not in disabled.get("macs", [])

    def test_no_policy_disables_nothing(self):
        assert preflight.build_disabled_algorithms(None) is None


class TestVerifiedSemantics:
    def test_a_run_that_never_authenticated_is_not_verified(self):
        result = preflight.PreflightResult(
            checks=[
                schemas.serialize_check(
                    schemas.CHECK_ADDRESS,
                    schemas.STATUS_PASS,
                    schemas.REASON_VERIFIED,
                ),
                schemas.serialize_check(
                    schemas.CHECK_NETWORK,
                    schemas.STATUS_PASS,
                    schemas.REASON_VERIFIED,
                ),
            ]
        )
        assert result.verified is False

    def test_any_failure_defeats_verification(self):
        result = preflight.PreflightResult(
            checks=[
                schemas.serialize_check(
                    schemas.CHECK_AUTHENTICATION,
                    schemas.STATUS_PASS,
                    schemas.REASON_VERIFIED,
                ),
                schemas.serialize_check(
                    schemas.CHECK_COMMAND,
                    schemas.STATUS_FAIL,
                    schemas.REASON_COMMAND_FAILED,
                ),
            ]
        )
        assert result.verified is False
        assert result.reason_code() == schemas.REASON_COMMAND_FAILED

    def test_a_skipped_sudo_check_does_not_defeat_verification(self):
        result = preflight.PreflightResult(
            checks=[
                schemas.serialize_check(
                    schemas.CHECK_AUTHENTICATION,
                    schemas.STATUS_PASS,
                    schemas.REASON_VERIFIED,
                ),
                schemas.serialize_check(
                    schemas.CHECK_SUDO,
                    schemas.STATUS_SKIPPED,
                    schemas.REASON_VERIFIED,
                ),
            ]
        )
        assert result.verified is True
        assert result.reason_code() == schemas.REASON_VERIFIED


class TestSudoClassification:
    @pytest.mark.parametrize(
        "stderr,expected",
        [
            ("sudo: a password is required", schemas.REASON_SUDO_PASSWORD_REQUIRED),
            (
                "sudo: no tty present and no askpass program specified",
                schemas.REASON_SUDO_PASSWORD_REQUIRED,
            ),
            ("praxis is not in the sudoers file.", schemas.REASON_SUDO_DENIED),
            ("Sorry, user praxis may not run sudo", schemas.REASON_SUDO_DENIED),
            ("bash: sudo: command not found", schemas.REASON_SUDO_UNAVAILABLE),
            ("something else entirely", schemas.REASON_SUDO_DENIED),
        ],
    )
    def test_stderr_maps_to_a_code(self, stderr, expected):
        assert preflight._classify_sudo_failure(stderr) == expected

    def test_a_credential_with_no_sudo_method_skips_rather_than_fails(self):
        credential = Credential(name="c", auth_method="password", sudo_method="none")
        check = preflight._probe_sudo(MagicMock(), credential, {})
        assert check["status"] == schemas.STATUS_SKIPPED

    def test_password_sudo_without_a_stored_password_is_reported(self):
        credential = Credential(
            name="c", auth_method="password", sudo_method="password"
        )
        check = preflight._probe_sudo(MagicMock(), credential, {})
        assert check["status"] == schemas.STATUS_FAIL
        assert check["reason_code"] == schemas.REASON_SUDO_PASSWORD_REQUIRED


class TestUsernameResolution:
    def test_a_credential_username_is_used(self):
        credential = Credential(name="c", auth_method="password", username="praxis")
        assert preflight._resolve_username(credential, {}) == "praxis"

    def test_a_vault_username_is_used_when_the_credential_has_none(self):
        credential = Credential(name="c", auth_method="password", username=None)
        assert preflight._resolve_username(credential, {"username": "root"}) == "root"

    def test_no_username_anywhere_is_a_structured_failure(self):
        credential = Credential(name="c", auth_method="password", username=None)
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._resolve_username(credential, {})
        assert excinfo.value.reason_code == schemas.REASON_USERNAME_MISSING

    def test_a_blank_username_is_treated_as_missing(self):
        credential = Credential(name="c", auth_method="password", username="   ")
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._resolve_username(credential, {})
        assert excinfo.value.reason_code == schemas.REASON_USERNAME_MISSING


def _private_key_pem(kind: str) -> str:
    """Generate a real private key of ``kind`` in OpenSSH PEM form."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if kind == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif kind == "ecdsa":
        key = ec.generate_private_key(ec.SECP256R1())
    elif kind == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:  # pragma: no cover - guard
        raise AssertionError(kind)

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


class TestCredentialKeyFormats:
    """Verification must accept the key types operators actually generate."""

    @pytest.mark.parametrize("kind", ["ed25519", "ecdsa", "rsa"])
    def test_supported_key_types_authenticate(self, kind):
        credential = Credential(
            name=f"key-{kind}", auth_method="ssh_key", username="praxis"
        )
        transport = MagicMock()
        preflight._authenticate(
            transport, credential, {"ssh_key": _private_key_pem(kind)}, None
        )
        transport.auth_publickey.assert_called_once()
        assert transport.auth_publickey.call_args[0][0] == "praxis"

    def test_an_unusable_key_maps_to_key_type_unsupported(self):
        credential = Credential(
            name="key-bad", auth_method="ssh_key", username="praxis"
        )
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._authenticate(
                MagicMock(),
                credential,
                {
                    "ssh_key": "-----BEGIN DSA PRIVATE KEY-----\nx\n-----END DSA PRIVATE KEY-----"
                },
                None,
            )
        assert excinfo.value.reason_code == schemas.REASON_KEY_TYPE_UNSUPPORTED

    def test_a_rejected_key_maps_to_authentication_failed(self):
        credential = Credential(
            name="key-rej", auth_method="ssh_key", username="praxis"
        )
        transport = MagicMock()
        transport.auth_publickey.side_effect = paramiko.AuthenticationException("no")
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._authenticate(
                transport, credential, {"ssh_key": _private_key_pem("ed25519")}, None
            )
        assert excinfo.value.reason_code == schemas.REASON_AUTHENTICATION_FAILED

    def test_a_wrong_password_maps_to_authentication_failed(self):
        credential = Credential(name="pw", auth_method="password", username="praxis")
        transport = MagicMock()
        transport.auth_password.side_effect = paramiko.AuthenticationException("no")
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._authenticate(transport, credential, {"password": "wrong"}, None)
        assert excinfo.value.reason_code == schemas.REASON_AUTHENTICATION_FAILED

    def test_a_password_credential_with_no_password_fails_authentication(self):
        credential = Credential(name="pw2", auth_method="password", username="praxis")
        with pytest.raises(preflight.PreflightError) as excinfo:
            preflight._authenticate(MagicMock(), credential, {}, None)
        assert excinfo.value.reason_code == schemas.REASON_AUTHENTICATION_FAILED


class TestDistributionReading:
    def test_debian_family_is_recognised(self):
        os_release = {"ID": "ubuntu", "ID_LIKE": "debian"}
        assert preflight.package_family_for(os_release) == "deb"
        assert preflight.package_manager_for("deb") == "apt"

    def test_enterprise_linux_family_is_recognised(self):
        os_release = {"ID": "rocky", "ID_LIKE": "rhel centos fedora"}
        assert preflight.package_family_for(os_release) == "rpm"
        assert preflight.package_manager_for("rpm") == "dnf"

    def test_id_like_resolves_a_derivative(self):
        os_release = {"ID": "somethingnew", "ID_LIKE": "debian"}
        assert preflight.package_family_for(os_release) == "deb"

    def test_an_unknown_distribution_maps_to_nothing(self):
        assert preflight.package_family_for({"ID": "plan9"}) is None
        assert preflight.package_manager_for(None) is None

    def test_os_release_parsing_strips_quotes_and_comments(self):
        parsed = preflight._parse_os_release(
            "# comment\nID=debian\nVERSION_ID=\"12\"\nNAME='Debian GNU/Linux'\njunk\n"
        )
        assert parsed["ID"] == "debian"
        assert parsed["VERSION_ID"] == "12"
        assert parsed["NAME"] == "Debian GNU/Linux"

    def test_identity_and_os_release_split_cleanly(self):
        identity, os_release = preflight._parse_identity(
            "PRAXIS_HOSTNAME=web-01\n"
            "PRAXIS_FQDN=web-01.example.test\n"
            "PRAXIS_ARCH=x86_64\n"
            "ID=debian\n"
            "VERSION_ID=12\n"
        )
        assert identity["hostname"] == "web-01"
        assert identity["fqdn"] == "web-01.example.test"
        assert identity["arch"] == "x86_64"
        assert os_release["ID"] == "debian"

    def test_an_empty_probe_value_reads_as_absent(self):
        identity, _ = preflight._parse_identity("PRAXIS_FQDN=\n")
        assert identity["fqdn"] is None


class TestAddressValidation:
    @pytest.mark.parametrize(
        "address", ["10.0.0.1", "2001:db8::1", "host-01", "host.example.test"]
    )
    def test_accepted_addresses(self, address):
        assert schemas.validate_address(address) == address

    @pytest.mark.parametrize("address", ["", "   ", "-bad", "a" * 300, "10.0.0.1/24"])
    def test_rejected_addresses(self, address):
        with pytest.raises(ValueError):
            schemas.validate_address(address)


class TestTagBounds:
    def test_tags_are_deduplicated_and_order_preserved(self):
        assert schemas.validate_tags(["b", "a", "b", " a "]) == ["b", "a"]

    def test_too_many_tags_are_refused(self):
        with pytest.raises(ValueError):
            schemas.validate_tags([f"t{i}" for i in range(schemas.MAX_TAGS + 1)])

    def test_an_overlong_tag_is_refused(self):
        with pytest.raises(ValueError):
            schemas.validate_tags(["x" * (schemas.TAG_MAX_LEN + 1)])
