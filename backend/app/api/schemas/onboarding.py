"""Typed contracts for the guided first-system onboarding flow.

Every value that reaches a draft's JSONB column is defined here and rendered by
an explicit serializer. Routes never hand a raw request dictionary to the
persistence layer: the schema is the boundary, and the serializers below decide
exactly which keys are written. That ordering matters more than any pattern
scan, because a key nobody serializes cannot be persisted no matter what a
client sends.

Verification results carry structured reason codes. Operator-facing text is
derived from the code, not from the exception that produced it, so transport
and library diagnostics never reach the browser or the database.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

# --------------------------------------------------------------------------- #
# Bounds                                                                       #
#                                                                             #
# A draft is operator-supplied storage, so every field it holds is bounded.    #
# The limits mirror the columns the values eventually land in, so a value that #
# passes here cannot fail on the way into `systems` / `system_metadata`.       #
# --------------------------------------------------------------------------- #

ADDRESS_MAX_LEN = 255
HOSTNAME_MAX_LEN = 255
DESCRIPTION_MAX_LEN = 4096
TAG_MAX_LEN = 100
MAX_TAGS = 32
UPDATE_POLICY_MAX_LEN = 50
MESSAGE_MAX_LEN = 512
DISCOVERY_VALUE_MAX_LEN = 255

SSH_PORT_MIN = 1
SSH_PORT_MAX = 65535
DEFAULT_SSH_PORT = 22

# Serialized ceiling for any single JSONB column. Well above a legitimate draft
# and far below anything that would make the table a storage surface.
MAX_JSON_BYTES = 16 * 1024

# How a draft came to know which distribution it is looking at. ``matched`` is
# discovery mapping the host's own os-release onto the catalogue, ``unknown`` is
# discovery finding no mapping for it, and ``declared`` is the operator naming
# the distribution when verification was skipped and nothing was read from the
# host at all. ``unknown`` describes what discovery found, not a state a draft
# can be finished in: the step still requires a catalogue row before it
# completes.
SUPPORT_MAPPING_MATCHED = "matched"
SUPPORT_MAPPING_UNKNOWN = "unknown"
SUPPORT_MAPPING_DECLARED = "declared"

ENVIRONMENTS = ("Production", "Staging", "Development", "Testing")
TRANSPORT_PREFERENCES = ("auto", "ssh", "agent")

# RFC 1123, matching the existing registration validator so the wizard and
# direct registration accept exactly the same hostnames.
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


# --------------------------------------------------------------------------- #
# Verification vocabulary                                                      #
# --------------------------------------------------------------------------- #

CHECK_ADDRESS = "address"
CHECK_NETWORK = "network"
CHECK_HOST_IDENTITY = "host_identity"
CHECK_AUTHENTICATION = "authentication"
CHECK_COMMAND = "command"
CHECK_SUDO = "sudo"

VERIFICATION_CHECKS = (
    CHECK_ADDRESS,
    CHECK_NETWORK,
    CHECK_HOST_IDENTITY,
    CHECK_AUTHENTICATION,
    CHECK_COMMAND,
    CHECK_SUDO,
)

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"

CHECK_STATUSES = (STATUS_PASS, STATUS_FAIL, STATUS_SKIPPED)

REASON_VERIFIED = "verified"
REASON_ADDRESS_INVALID = "address_invalid"
REASON_NETWORK_UNREACHABLE = "network_unreachable"
REASON_CONNECTION_TIMEOUT = "connection_timeout"
REASON_HOST_KEY_UNKNOWN = "host_key_unknown"
REASON_HOST_KEY_MISMATCH = "host_key_mismatch"
REASON_SSH_POLICY_REJECTED = "ssh_policy_rejected"
REASON_AUTHENTICATION_FAILED = "authentication_failed"
REASON_USERNAME_MISSING = "username_missing"
REASON_KEY_TYPE_UNSUPPORTED = "key_type_unsupported"
REASON_COMMAND_FAILED = "command_failed"
REASON_SUDO_PASSWORD_REQUIRED = "sudo_password_required"
REASON_SUDO_DENIED = "sudo_denied"
REASON_SUDO_UNAVAILABLE = "sudo_unavailable"

REASON_CODES = (
    REASON_VERIFIED,
    REASON_ADDRESS_INVALID,
    REASON_NETWORK_UNREACHABLE,
    REASON_CONNECTION_TIMEOUT,
    REASON_HOST_KEY_UNKNOWN,
    REASON_HOST_KEY_MISMATCH,
    REASON_SSH_POLICY_REJECTED,
    REASON_AUTHENTICATION_FAILED,
    REASON_USERNAME_MISSING,
    REASON_KEY_TYPE_UNSUPPORTED,
    REASON_COMMAND_FAILED,
    REASON_SUDO_PASSWORD_REQUIRED,
    REASON_SUDO_DENIED,
    REASON_SUDO_UNAVAILABLE,
)

# The single source of operator-facing wording. Verification never surfaces the
# underlying exception, so a transport message cannot leak a path, a key, or an
# internal hostname through an error string.
REASON_MESSAGES: Dict[str, str] = {
    REASON_VERIFIED: "Verified.",
    REASON_ADDRESS_INVALID: (
        "The address is not a valid IPv4 address, IPv6 address, or hostname."
    ),
    REASON_NETWORK_UNREACHABLE: (
        "No route to the host on that port. Check the address, the SSH port, "
        "and any firewall between Praxis and the host."
    ),
    REASON_CONNECTION_TIMEOUT: (
        "The host did not answer in time. It may be offline, or traffic on that "
        "port may be dropped rather than refused."
    ),
    REASON_HOST_KEY_UNKNOWN: (
        "Praxis has not seen this host before. Review the fingerprint and "
        "confirm it matches the host you intend to manage."
    ),
    REASON_HOST_KEY_MISMATCH: (
        "The host offered a different key than the one approved for this setup. "
        "This can mean the host was rebuilt, or that something is impersonating "
        "it. Verification stops here."
    ),
    REASON_SSH_POLICY_REJECTED: (
        "The SSH policy in force rejected the connection. The host and Praxis "
        "have no acceptable algorithm in common, or the host key type is not "
        "permitted."
    ),
    REASON_AUTHENTICATION_FAILED: (
        "The host refused the credential. Check the username, the secret, and "
        "whether the account is permitted to log in over SSH."
    ),
    REASON_USERNAME_MISSING: (
        "This credential has no username, and none could be derived from it. "
        "Add a username to the credential and try again."
    ),
    REASON_KEY_TYPE_UNSUPPORTED: (
        "The credential's private key is not in a supported format. Use an "
        "Ed25519, ECDSA, or RSA key."
    ),
    REASON_COMMAND_FAILED: (
        "Connected and authenticated, but a basic command did not run cleanly. "
        "The account may have a restricted shell."
    ),
    REASON_SUDO_PASSWORD_REQUIRED: (
        "Elevation needs a password that this credential does not carry. Add a "
        "sudo password to the credential, or grant passwordless sudo."
    ),
    REASON_SUDO_DENIED: ("The account is not permitted to elevate on this host."),
    REASON_SUDO_UNAVAILABLE: ("No usable sudo was found on the host."),
}


def message_for(reason_code: str) -> str:
    """Operator-facing text for a reason code, derived only from the code."""
    return REASON_MESSAGES.get(reason_code, "Verification could not be completed.")


# --------------------------------------------------------------------------- #
# Shared field validators                                                      #
# --------------------------------------------------------------------------- #


def _clean_optional_text(value: Any, *, field: str, max_len: int) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value:
        return None
    if len(value) > max_len:
        raise ValueError(f"{field} must be at most {max_len} characters")
    return value


def validate_address(value: Any) -> str:
    """Accept an IPv4 address, an IPv6 address, or an RFC 1123 hostname."""
    if not isinstance(value, str):
        raise ValueError("address must be a string")
    value = value.strip()
    if not value:
        raise ValueError("address is required")
    if len(value) > ADDRESS_MAX_LEN:
        raise ValueError(f"address must be at most {ADDRESS_MAX_LEN} characters")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(value):
        raise ValueError("address must be an IPv4 address, IPv6 address, or hostname")
    return value


def validate_tags(value: Any) -> List[str]:
    """Bounded, de-duplicated, order-preserving tag list."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("tags must be a list")
    if len(value) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags are allowed")
    cleaned: List[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError("each tag must be a string")
        entry = entry.strip()
        if not entry:
            continue
        if len(entry) > TAG_MAX_LEN:
            raise ValueError(f"each tag must be at most {TAG_MAX_LEN} characters")
        if entry not in cleaned:
            cleaned.append(entry)
    return cleaned


# --------------------------------------------------------------------------- #
# Step request bodies                                                          #
# --------------------------------------------------------------------------- #


class ConnectStep(BaseModel):
    """Step 1. Where the host is, and optionally what to call it.

    Distro, group, environment and status are deliberately absent: the operator
    should not have to describe a host before Praxis has looked at it.
    """

    address: str = Field(..., description="IPv4 address, IPv6 address, or hostname")
    ssh_port: int = Field(DEFAULT_SSH_PORT, description="SSH port")
    hostname: Optional[str] = Field(
        None, description="Proposed display hostname; discovery may refine it"
    )

    @validator("address")
    def _address(cls, v):  # pylint: disable=no-self-argument
        return validate_address(v)

    @validator("ssh_port", pre=True)
    def _port(cls, v):  # pylint: disable=no-self-argument
        # pre=True with an explicit bool guard: bool is an int subclass, so
        # `True` would otherwise sail through as port 1.
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("ssh_port must be an integer")
        if not SSH_PORT_MIN <= v <= SSH_PORT_MAX:
            raise ValueError(f"ssh_port must be {SSH_PORT_MIN}..{SSH_PORT_MAX}")
        return v

    @validator("hostname")
    def _hostname(cls, v):  # pylint: disable=no-self-argument
        v = _clean_optional_text(v, field="hostname", max_len=HOSTNAME_MAX_LEN)
        if v is not None and not _HOSTNAME_RE.match(v):
            raise ValueError("hostname must be a valid RFC 1123 hostname")
        return v


class AuthenticateStep(BaseModel):
    """Step 2. Which stored credential and SSH policy this host will use.

    Only references. Creating a credential is a separate, already-authorized
    call; the wizard records the id it returns.
    """

    credential_id: int = Field(..., description="Existing credential to use")
    ssh_security_policy_id: Optional[int] = Field(
        None, description="SSH security policy; the Default policy when omitted"
    )

    @validator("credential_id", pre=True)
    def _credential_id(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("credential_id must be an integer")
        if v < 1:
            raise ValueError("credential_id must be positive")
        return v

    @validator("ssh_security_policy_id", pre=True)
    def _policy_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("ssh_security_policy_id must be an integer")
        if v < 1:
            raise ValueError("ssh_security_policy_id must be positive")
        return v


class HostKeyDecisionStep(BaseModel):
    """Step 3 decision. The operator accepts or rejects the offered key.

    ``fingerprint`` is what the operator actually looked at. It must still match
    what the draft captured, so a key that changed between display and decision
    cannot be approved by a stale click.
    """

    accept: bool = Field(..., description="True to trust the offered host key")
    fingerprint: str = Field(..., description="Fingerprint the operator reviewed")

    @validator("accept", pre=True)
    def _accept(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, bool):
            raise ValueError("accept must be a boolean")
        return v

    @validator("fingerprint")
    def _fingerprint(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("fingerprint is required")
        return v.strip()


class SkipVerificationStep(BaseModel):
    """Explicitly declining verification. Never a default, always a choice."""

    acknowledged: bool = Field(
        ..., description="Operator acknowledges the host will not be Active"
    )

    @validator("acknowledged", pre=True)
    def _acknowledged(cls, v):  # pylint: disable=no-self-argument
        if v is not True:
            raise ValueError("verification can only be skipped with acknowledgement")
        return v


class DiscoveryConfirmStep(BaseModel):
    """Step 4 confirmation: which supported release this host is bound to.

    ``confirmed_unknown`` is accepted and recorded, but it is not a way through
    the step. A host with no catalogue mapping cannot be patched, rolled back,
    mirrored or assessed, so there is no acknowledgement that makes one
    manageable, and the step is refused without a distribution whatever the flag
    says. It is still read rather than rejected so a client carrying the older
    shape, which sent it alongside a real choice, is not refused for that alone.
    """

    distro_id: Optional[int] = Field(
        None, description="The supported release this host is bound to"
    )
    confirmed_unknown: bool = Field(
        False, description="Legacy acknowledgement; never sufficient on its own"
    )

    @validator("distro_id", pre=True)
    def _distro_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("distro_id must be an integer")
        if v < 1:
            raise ValueError("distro_id must be positive")
        return v

    @validator("confirmed_unknown", pre=True)
    def _confirmed(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, bool):
            raise ValueError("confirmed_unknown must be a boolean")
        return v


class OrganizeStep(BaseModel):
    """Step 5. Where the host belongs and how it is labelled.

    Lifecycle status is absent by design: it is decided by whether verification
    succeeded, not by asking the operator to assert it.
    """

    group_id: Optional[int] = Field(None, description="Placement group")
    environment: Optional[str] = Field(None, description="Environment label")
    description: Optional[str] = Field(None, description="Free-text description")
    tags: Optional[List[str]] = Field(None, description="Tag names")
    transport_preference: Optional[str] = Field(None, description="auto, ssh, or agent")
    update_policy: Optional[str] = Field(None, description="Update policy")

    @validator("group_id", pre=True)
    def _group_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("group_id must be an integer")
        if v < 1:
            raise ValueError("group_id must be positive")
        return v

    @validator("environment")
    def _environment(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if v not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of: {', '.join(ENVIRONMENTS)}")
        return v

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _clean_optional_text(v, field="description", max_len=DESCRIPTION_MAX_LEN)

    @validator("tags")
    def _tags(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return validate_tags(v)

    @validator("transport_preference")
    def _transport(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if v not in TRANSPORT_PREFERENCES:
            raise ValueError(
                f"transport_preference must be one of: "
                f"{', '.join(TRANSPORT_PREFERENCES)}"
            )
        return v

    @validator("update_policy")
    def _update_policy(cls, v):  # pylint: disable=no-self-argument
        return _clean_optional_text(
            v, field="update_policy", max_len=UPDATE_POLICY_MAX_LEN
        )


class FinishStep(BaseModel):
    """Step 7. Finalization, gated on the token issued at Confirm."""

    finalize_token: str = Field(..., description="Token issued when Confirm was built")
    state_version: int = Field(..., description="Draft version the operator confirmed")

    @validator("finalize_token")
    def _token(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("finalize_token is required")
        return v.strip()

    @validator("state_version", pre=True)
    def _version(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("state_version must be an integer")
        if v < 0:
            raise ValueError("state_version must not be negative")
        return v


# --------------------------------------------------------------------------- #
# Serializers: the only writers of draft JSONB                                 #
# --------------------------------------------------------------------------- #


def serialize_connection(
    step: ConnectStep, *, resolved_ip: Optional[str] = None
) -> Dict[str, Any]:
    """Exactly the connection keys a draft may hold.

    ``resolved_ip`` is what verification actually connected to. A host may be
    named rather than addressed, and registration needs a concrete address, so
    the resolution is recorded rather than repeated later against a DNS answer
    that may since have changed.
    """
    return {
        "address": step.address,
        "ssh_port": step.ssh_port,
        "hostname": step.hostname,
        "resolved_ip": resolved_ip,
    }


def serialize_organization(
    step: OrganizeStep, existing: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Merge an organize step over existing draft state.

    Omitted fields leave the stored value alone; an explicitly supplied value
    replaces it. That is the same omission-versus-null rule the registration
    API follows, so the wizard and a direct API caller behave identically.
    """
    current = dict(existing or {})
    supplied = step.dict(exclude_unset=True)

    for key in (
        "group_id",
        "environment",
        "description",
        "transport_preference",
        "update_policy",
    ):
        if key in supplied:
            current[key] = supplied[key]
    if "tags" in supplied:
        current["tags"] = supplied["tags"] or []

    current.setdefault("tags", [])
    return current


def serialize_check(
    check: str, status: str, reason_code: str, detail: Optional[str] = None
) -> Dict[str, Any]:
    """One verification check result. Text comes from the code, never a caller."""
    if check not in VERIFICATION_CHECKS:
        raise ValueError(f"unknown verification check: {check}")
    if status not in CHECK_STATUSES:
        raise ValueError(f"unknown check status: {status}")
    if reason_code not in REASON_CODES:
        raise ValueError(f"unknown reason code: {reason_code}")
    result: Dict[str, Any] = {
        "check": check,
        "status": status,
        "reason_code": reason_code,
        "message": message_for(reason_code),
    }
    if detail:
        result["detail"] = detail[:MESSAGE_MAX_LEN]
    return result


def serialize_verification(
    checks: List[Dict[str, Any]],
    *,
    verified: bool,
    completed_at: str,
    host_key_fingerprint: Optional[str] = None,
    host_key_type: Optional[str] = None,
) -> Dict[str, Any]:
    """The verification block a draft stores: codes, booleans, timestamps."""
    return {
        "verified": bool(verified),
        "completed_at": completed_at,
        "checks": checks,
        "host_key_fingerprint": host_key_fingerprint,
        "host_key_type": host_key_type,
    }


def serialize_discovery(
    *,
    effective_hostname: Optional[str],
    fqdn: Optional[str],
    distro_name: Optional[str],
    distro_version: Optional[str],
    architecture: Optional[str],
    package_family: Optional[str],
    package_manager: Optional[str],
    support_mapping: str,
    distro_id: Optional[int],
    confirmed_unknown: bool,
    collected_at: str,
) -> Dict[str, Any]:
    """Exactly the discovery keys a draft may hold, each bounded."""

    def _bounded(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return str(value)[:DISCOVERY_VALUE_MAX_LEN]

    return {
        "effective_hostname": _bounded(effective_hostname),
        "fqdn": _bounded(fqdn),
        "distro_name": _bounded(distro_name),
        "distro_version": _bounded(distro_version),
        "architecture": _bounded(architecture),
        "package_family": _bounded(package_family),
        "package_manager": _bounded(package_manager),
        "support_mapping": support_mapping,
        "distro_id": distro_id,
        "confirmed_unknown": bool(confirmed_unknown),
        "collected_at": collected_at,
    }
