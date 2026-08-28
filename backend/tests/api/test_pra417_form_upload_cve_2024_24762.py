"""PRA-417: form and upload surfaces after the CVE-2024-24762 pin correction.

CVE-2024-24762 is a denial of service in the ``Content-Type`` option-header
parser that Starlette calls for every form and multipart request. Below
``python-multipart`` 0.0.7 that parser was a backtracking regular expression
whose quoted-string alternation blows up exponentially on a ``boundary`` value
that opens a quoted string and never closes it, stalling the event loop. 0.0.7
replaced it with a linear ``email.message`` based parser.

FastAPI 0.109.0 declared a floor of ``python-multipart>=0.0.5``, so a resolved
environment could satisfy the framework and still install the vulnerable
parser. FastAPI 0.109.1 raises that declared floor to ``>=0.0.7`` and is the
smallest release that closes the advisory.

These tests guard the dependency contract and the two request surfaces that
reach the parser:

- the pinned, declared, and installed dependency floors;
- the option-header parser Starlette imports, checked on parse results rather
  than elapsed time so the test is deterministic under load;
- ``POST /auth/login``, which reads ``application/x-www-form-urlencoded``
  through ``OAuth2PasswordRequestForm``; and
- ``POST /transfer/{system_id}/upload``, which reads ``multipart/form-data``
  into an ``UploadFile`` and streams it to the transfer service.
"""

from __future__ import annotations

import re
from importlib.metadata import requires as dist_requires
from importlib.metadata import version as dist_version
from pathlib import Path
from typing import Optional, Tuple

import pytest

# The exact symbol starlette.formparsers imports for every form request.
from multipart.multipart import parse_options_header

from app.api.routes import file_transfer as file_transfer_route

BACKEND = Path(__file__).resolve().parents[2]
REQUIREMENTS = BACKEND / "requirements.txt"

# Lowest releases that carry the fix. Raising either floor is deliberate: bump
# the constant in the same change that bumps requirements.txt.
MINIMUM_FASTAPI = (0, 109, 1)
MINIMUM_MULTIPART = (0, 0, 7)

PIN_PATTERN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?==(?P<version>\S+)")
FLOOR_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*>=\s*(?P<version>[0-9][0-9A-Za-z.]*)"
)


def _version_tuple(raw: str) -> Tuple[int, ...]:
    """Numeric release segments of a version string, ignoring any suffix."""
    parts = []
    for segment in raw.split("."):
        match = re.match(r"\d+", segment)
        if not match:
            break
        parts.append(int(match.group()))
    assert parts, f"no numeric release segment in {raw!r}"
    return tuple(parts)


def _pinned(name: str) -> Optional[str]:
    """The ``==`` pin recorded for ``name`` in requirements.txt."""
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = PIN_PATTERN.match(stripped)
        if match and match.group("name").lower() == name:
            return match.group("version")
    return None


def _declared_floor(distribution: str, dependency: str) -> Optional[str]:
    """The ``>=`` floor ``distribution`` declares for ``dependency``."""
    for requirement in dist_requires(distribution) or []:
        match = FLOOR_PATTERN.match(requirement.strip())
        if match and match.group("name").lower() == dependency:
            return match.group("version")
    return None


def _unterminated_quote_header(backslashes: int) -> bytes:
    """The advisory's header shape: a boundary that opens a quote and never closes it.

    The superseded regex could not match this at all and burned exponential time
    proving it; the corrected parser returns the raw token immediately.
    """
    return b'multipart/form-data; boundary="' + b"\\" * backslashes + b"!"


# --------------------------------------------------------------------------
# Dependency floors
# --------------------------------------------------------------------------


def test_requirements_pins_fastapi_at_or_above_the_advisory_floor():
    pinned = _pinned("fastapi")
    assert pinned is not None, "fastapi is no longer pinned in requirements.txt"
    assert _version_tuple(pinned) >= MINIMUM_FASTAPI, (
        f"requirements.txt pins fastapi=={pinned}; CVE-2024-24762 needs "
        f"{'.'.join(str(p) for p in MINIMUM_FASTAPI)} or newer"
    )


def test_installed_fastapi_is_at_or_above_the_advisory_floor():
    installed = dist_version("fastapi")
    assert _version_tuple(installed) >= MINIMUM_FASTAPI, (
        f"installed fastapi is {installed}; the environment still carries the "
        "release that declares python-multipart>=0.0.5"
    )


def test_fastapi_declares_the_corrected_multipart_floor():
    """The advisory is about what FastAPI lets a resolver install, not only our pin."""
    floor = _declared_floor("fastapi", "python-multipart")
    assert floor is not None, "fastapi no longer declares a python-multipart floor"
    assert _version_tuple(floor) >= MINIMUM_MULTIPART, (
        f"fastapi declares python-multipart>={floor}; a resolver could still "
        "select the backtracking parser"
    )


def test_installed_multipart_is_at_or_above_the_advisory_floor():
    installed = dist_version("python-multipart")
    assert _version_tuple(installed) >= MINIMUM_MULTIPART


# --------------------------------------------------------------------------
# Option-header parser
# --------------------------------------------------------------------------


def test_unterminated_quote_boundary_parses_to_a_value():
    """Deterministic fingerprint of the corrected parser.

    The backtracking regex required a closing quote, so it returned no options
    for this header. The linear parser reports the boundary token verbatim.
    Asserting on the parsed value rather than elapsed time keeps the check
    stable on a loaded machine.
    """
    ctype, options = parse_options_header(_unterminated_quote_header(8))
    assert ctype == b"multipart/form-data"
    assert options.get(b"boundary") == b'"' + b"\\" * 8 + b"!"


@pytest.mark.parametrize("backslashes", [8, 16, 64, 512])
def test_unterminated_quote_boundary_scales_linearly(backslashes):
    """Every length parses; the superseded regex doubled its work per backslash."""
    ctype, options = parse_options_header(_unterminated_quote_header(backslashes))
    assert ctype == b"multipart/form-data"
    assert options.get(b"boundary") == b'"' + b"\\" * backslashes + b"!"


def test_well_formed_option_headers_still_parse():
    """The parser swap must not change how real headers are read."""
    assert parse_options_header(b"application/x-www-form-urlencoded") == (
        b"application/x-www-form-urlencoded",
        {},
    )
    ctype, options = parse_options_header(
        b'multipart/form-data; boundary="abc123"; charset=utf-8'
    )
    assert ctype == b"multipart/form-data"
    assert options[b"boundary"] == b"abc123"
    assert options[b"charset"] == b"utf-8"


# --------------------------------------------------------------------------
# POST /auth/login (application/x-www-form-urlencoded)
# --------------------------------------------------------------------------


def test_login_form_still_yields_tokens(client, admin_user):
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_login_form_missing_field_is_rejected_by_validation(client, admin_user):
    res = client.post("/auth/login", data={"username": admin_user.username})
    assert res.status_code == 422, res.text


def test_login_form_wrong_password_still_fails_closed(client, admin_user):
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "wrong-password"},
    )
    assert res.status_code == 401, res.text


def test_login_form_decodes_reserved_characters(client, admin_user):
    """Percent- and plus-encoded values must reach authentication intact.

    A credential of literal spaces and separators has to be rejected as a bad
    password, not mangled into something the form parser drops.
    """
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": 'a b+c%d;e"f'},
    )
    assert res.status_code == 401, res.text


def test_login_rejects_the_advisory_content_type_without_stalling(client, admin_user):
    """The hostile header reaches the route and is answered, not hung on."""
    res = client.post(
        "/auth/login",
        content=b"",
        headers={"content-type": _unterminated_quote_header(512).decode("latin-1")},
    )
    assert 400 <= res.status_code < 500, res.text


# --------------------------------------------------------------------------
# POST /transfer/{system_id}/upload (multipart/form-data)
# --------------------------------------------------------------------------


@pytest.fixture
def captured_upload(monkeypatch):
    """Replace the transfer service so only route-level multipart handling runs.

    The SSH/agent transports are out of scope here; what matters is that the
    parsed ``UploadFile`` reaches the service with its filename and full body.
    """
    captured = {}

    def _fake_upload_stream(db, user, system_id, remote_path, iterator, **kwargs):
        captured["system_id"] = system_id
        captured["remote_path"] = remote_path
        captured["body"] = b"".join(iterator)
        captured["local_filename"] = kwargs.get("local_filename")
        captured["client_ip"] = kwargs.get("client_ip")
        return {"bytes": len(captured["body"]), "transport": "ssh"}

    monkeypatch.setattr(file_transfer_route.fts, "upload_stream", _fake_upload_stream)
    return captured


def test_upload_streams_a_multipart_body_larger_than_one_chunk(
    authed_client, captured_upload
):
    """The route reads the part in 64 KiB chunks, so cross a chunk boundary."""
    payload = bytes(range(256)) * 700  # ~175 KiB
    res = authed_client.post(
        "/transfer/7/upload",
        params={"path": "/tmp/praxis-upload.bin"},
        files={"file": ("praxis-upload.bin", payload, "application/octet-stream")},
    )
    assert res.status_code == 200, res.text
    assert res.json() == {
        "status": "success",
        "bytes": len(payload),
        "transport": "ssh",
    }
    assert captured_upload["body"] == payload
    assert captured_upload["system_id"] == 7
    assert captured_upload["remote_path"] == "/tmp/praxis-upload.bin"
    assert captured_upload["local_filename"] == "praxis-upload.bin"


def test_upload_preserves_a_filename_with_option_header_separators(
    authed_client, captured_upload
):
    """The part's Content-Disposition goes through the same option parser.

    Hand-built so the separators survive the client: a quoted filename holding a
    semicolon, a space, and a backslash-escaped quote is exactly the shape the
    superseded regex unquoted by hand and the corrected parser must still read
    the same way.
    """
    boundary = "praxisboundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; '
        'filename="we;ird \\"name\\".txt"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        "payload\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    res = authed_client.post(
        "/transfer/7/upload",
        params={"path": "/tmp/dest.txt"},
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    )
    assert res.status_code == 200, res.text
    assert captured_upload["local_filename"] == 'we;ird "name".txt'
    assert captured_upload["body"] == b"payload"


def test_upload_without_a_file_part_is_a_client_error(authed_client, captured_upload):
    res = authed_client.post(
        "/transfer/7/upload",
        params={"path": "/tmp/dest.txt"},
        files={"notfile": ("x.txt", b"payload", "application/octet-stream")},
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == "file part required"
    assert captured_upload == {}


def test_upload_still_requires_authentication(client, captured_upload):
    res = client.post(
        "/transfer/7/upload",
        params={"path": "/tmp/dest.txt"},
        files={"file": ("x.txt", b"payload", "application/octet-stream")},
    )
    assert res.status_code == 401, res.text
    assert captured_upload == {}
