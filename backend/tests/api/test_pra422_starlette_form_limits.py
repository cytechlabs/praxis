"""PRA-422: form-parser limits after the Starlette denial-of-service corrections.

Starlette parses every form and multipart request the backend accepts, and three
denial-of-service advisories landed on that parser:

- CVE-2024-47874 (fixed in 0.40.0): a ``multipart/form-data`` part with no
  ``filename`` is treated as a text field and buffered in an unbounded byte
  string, so an arbitrarily large field exhausts memory.
- CVE-2025-54121 (fixed in 0.47.2): ``UploadFile.write`` checked only whether the
  spooled file had already rolled, so the write that *causes* the rollover ran
  inline and blocked the event loop.
- CVE-2026-54283 (fixed in 1.3.1): ``request.form()``'s ``max_fields`` and
  ``max_part_size`` were forwarded to the multipart parser but silently dropped
  for ``application/x-www-form-urlencoded``, leaving the urlencoded parser with
  no field-count and no field-size bound at all.

Both parsers are reachable from ``POST /auth/login``, which is in
``PUBLIC_EXACT_PATHS`` and whose form dependency is resolved before the route's
own rate limiter runs, so the exposure is pre-authentication.

These tests guard the dependency contract and each advisory's mechanism, and
pin the behaviour the corrections must NOT change: a file part still has no size
cap, so real uploads keep working.
"""

from __future__ import annotations

import ast
import re
from importlib.metadata import requires as dist_requires
from importlib.metadata import version as dist_version
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import List, Optional, Tuple

import pytest
from starlette import datastructures as starlette_datastructures
from starlette.datastructures import Headers, UploadFile

from app.api.routes import file_transfer as file_transfer_route

BACKEND = Path(__file__).resolve().parents[2]
REQUIREMENTS = BACKEND / "requirements.txt"
SETUP_PY = BACKEND / "setup.py"

# Lowest releases that carry the fixes. Raising either is deliberate: bump the
# constant in the same change that bumps the pin.
MINIMUM_FASTAPI = (0, 137, 0)
MINIMUM_STARLETTE = (1, 3, 1)

# Starlette's own defaults for a form request, and what the parser reports when
# a request crosses them.
FORM_MAX_PART_SIZE = 1024 * 1024
FORM_MAX_FIELDS = 1000

PIN_PATTERN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?==(?P<version>\S+)")
SPECIFIER_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?P<specifier>[<>=!~].*)$"
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


def _install_requires() -> List[str]:
    """``setup()``'s ``install_requires`` list, read without importing setup.py."""
    tree = ast.parse(SETUP_PY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg == "install_requires":
                return [ast.literal_eval(element) for element in keyword.value.elts]
    raise AssertionError("setup.py no longer calls setup(install_requires=[...])")


def _declared_specifier(distribution: str, dependency: str) -> Optional[str]:
    """The version specifier ``distribution`` declares for ``dependency``.

    Only the unconditional requirement is considered; a requirement carrying an
    environment marker (an ``extra ==`` line) is not what a plain install
    resolves against.
    """
    for requirement in dist_requires(distribution) or []:
        base = requirement.split(";", 1)[0].strip()
        match = SPECIFIER_PATTERN.match(base)
        if match and match.group("name").lower() == dependency:
            return match.group("specifier").strip()
    return None


def _urlencoded(client, body: str):
    return client.post(
        "/auth/login",
        content=body.encode(),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )


def _multipart_field(client, name: str, value: str):
    """A multipart body whose single part carries no ``filename``.

    That is exactly the shape CVE-2024-47874 describes: no filename means
    Starlette buffers the part as a text field rather than spooling it.
    """
    boundary = "praxisboundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n'
        "\r\n"
        f"{value}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return client.post(
        "/auth/login",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    )


# --------------------------------------------------------------------------
# Dependency contract
# --------------------------------------------------------------------------


def test_requirements_pins_starlette_at_or_above_the_advisory_floor():
    """Starlette is pinned directly; fastapi declares no upper bound on it."""
    pinned = _pinned("starlette")
    assert pinned is not None, (
        "starlette is not pinned in requirements.txt; fastapi declares no upper "
        "bound, so a rebuild would float onto an untested release"
    )
    assert _version_tuple(pinned) >= MINIMUM_STARLETTE, (
        f"requirements.txt pins starlette=={pinned}; CVE-2026-54283 needs "
        f"{'.'.join(str(p) for p in MINIMUM_STARLETTE)} or newer"
    )


def test_requirements_pins_fastapi_at_or_above_the_advisory_floor():
    pinned = _pinned("fastapi")
    assert pinned is not None, "fastapi is no longer pinned in requirements.txt"
    assert _version_tuple(pinned) >= MINIMUM_FASTAPI, (
        f"requirements.txt pins fastapi=={pinned}; the corrected starlette needs "
        f"{'.'.join(str(p) for p in MINIMUM_FASTAPI)} or newer"
    )


@pytest.mark.parametrize("name", ["fastapi", "starlette"])
def test_setup_py_declares_the_same_pin_as_requirements(name):
    """The wheel's own metadata must not resolve a different framework version."""
    pinned = _pinned(name)
    declared = [
        requirement
        for requirement in _install_requires()
        if requirement.split("==")[0].strip().lower() == name
    ]
    assert declared == [f"{name}=={pinned}"], (
        f"setup.py declares {declared} but requirements.txt pins {name}=={pinned}; "
        "installing the package would resolve a different framework version"
    )


def test_installed_versions_are_at_or_above_the_advisory_floors():
    assert _version_tuple(dist_version("starlette")) >= MINIMUM_STARLETTE
    assert _version_tuple(dist_version("fastapi")) >= MINIMUM_FASTAPI


def test_fastapi_admits_the_pinned_starlette():
    """A future fastapi bump must not cap starlette back below the fix.

    The advisory is about what the framework lets a resolver install, not only
    about the version this tree happens to pin. A pin outside the declared range
    would be unsupported constraint forcing rather than a supported upgrade.
    """
    specifier = _declared_specifier("fastapi", "starlette")
    assert specifier is not None, "fastapi no longer declares a starlette dependency"
    pinned = _version_tuple(_pinned("starlette"))

    for clause in specifier.split(","):
        match = re.match(r"^\s*(<=|>=|<|>|==)\s*(\S+)\s*$", clause)
        assert match, f"unhandled clause {clause!r} in fastapi's starlette range"
        operator, bound = match.group(1), _version_tuple(match.group(2))
        satisfied = {
            "<": pinned < bound,
            "<=": pinned <= bound,
            ">": pinned > bound,
            ">=": pinned >= bound,
            "==": pinned == bound,
        }[operator]
        assert satisfied, (
            f"fastapi declares starlette{specifier}, which excludes the pinned "
            f"{_pinned('starlette')}"
        )


# --------------------------------------------------------------------------
# CVE-2026-54283: urlencoded bodies are now bounded
# --------------------------------------------------------------------------


def test_oversized_urlencoded_field_is_rejected(client):
    """The advisory's memory shape: one field larger than ``max_part_size``.

    Before 1.3.1 the urlencoded parser had no size parameter at all, so this
    body was buffered in full and answered as a normal failed login.
    """
    oversized = "x" * (FORM_MAX_PART_SIZE + 1024)
    res = _urlencoded(client, f"username=a&password={oversized}")
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == "Field exceeded maximum size of 1024KB."


def test_excess_urlencoded_fields_are_rejected(client):
    """The advisory's event-loop shape: more fields than ``max_fields``."""
    body = "&".join(f"f{index}=v" for index in range(FORM_MAX_FIELDS + 1))
    res = _urlencoded(client, f"{body}&username=a&password=b")
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == (
        f"Too many fields. Maximum number of fields is {FORM_MAX_FIELDS}."
    )


def test_urlencoded_field_just_under_the_limit_is_still_parsed(client, admin_user):
    """The bound must reject the advisory's shape without narrowing real logins.

    A field just under the cap has to be parsed and handed to the route, so the
    login still succeeds. The bulk goes in a field the login form ignores rather
    than in the password, because passlib caps a credential at 4096 bytes long
    before the form parser's own limit would apply.
    """
    filler = "x" * (FORM_MAX_PART_SIZE - 64)
    res = _urlencoded(
        client,
        f"username={admin_user.username}&password=testpass123&note={filler}",
    )
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]


def test_login_still_yields_tokens(client, admin_user):
    """The ordinary urlencoded login is unchanged by the new limits."""
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]


# --------------------------------------------------------------------------
# CVE-2024-47874: unbounded non-file multipart parts
# --------------------------------------------------------------------------


def test_oversized_multipart_field_is_rejected(client):
    """A part with no ``filename`` is a text field and is now size-bounded."""
    res = _multipart_field(client, "password", "x" * (FORM_MAX_PART_SIZE + 1024))
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == "Part exceeded maximum size of 1024KB."


def test_small_multipart_field_still_reaches_validation(client):
    """The rejection above must come from the size bound, not from the shape.

    The same body under the cap parses and is answered by request validation,
    which proves the oversized case is not simply a malformed request.
    """
    res = _multipart_field(client, "password", "x" * 64)
    assert res.status_code == 422, res.text


# --------------------------------------------------------------------------
# CVE-2025-54121: the rollover write leaves the event loop
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollover_write_is_dispatched_off_the_event_loop(monkeypatch):
    """The write that causes the spool rollover must not run inline.

    The superseded code asked only whether the file had *already* rolled, so the
    write crossing the threshold took the in-memory branch and blocked the loop.
    Recording the threadpool calls pins the corrected dispatch directly, with no
    dependence on timing.
    """
    dispatched: List[int] = []
    original = starlette_datastructures.run_in_threadpool

    async def _recording_run_in_threadpool(func, *args, **kwargs):
        if args and isinstance(args[0], (bytes, bytearray)):
            dispatched.append(len(args[0]))
        return await original(func, *args, **kwargs)

    monkeypatch.setattr(
        starlette_datastructures, "run_in_threadpool", _recording_run_in_threadpool
    )

    spool_max = 1024
    with SpooledTemporaryFile(max_size=spool_max) as spooled:
        upload = UploadFile(
            file=spooled, size=0, filename="rollover.bin", headers=Headers()
        )

        await upload.write(b"a" * (spool_max // 2))
        assert dispatched == [], "a write that stays in memory must not be dispatched"

        await upload.write(b"b" * spool_max)
        assert dispatched == [spool_max], (
            "the write that crosses the spool threshold still ran inline; "
            "UploadFile.write is not consulting the projected size"
        )

        await upload.write(b"c" * 16)
        assert dispatched == [spool_max, 16], "writes after the rollover must dispatch"

        assert upload.size == (spool_max // 2) + spool_max + 16


# --------------------------------------------------------------------------
# The size bound must not reach file parts
# --------------------------------------------------------------------------


@pytest.fixture
def captured_upload(monkeypatch):
    """Replace the transfer service so only route-level multipart handling runs."""
    captured = {}

    def _fake_upload_stream(db, user, system_id, remote_path, iterator, **kwargs):
        captured["body"] = b"".join(iterator)
        captured["local_filename"] = kwargs.get("local_filename")
        return {"bytes": len(captured["body"]), "transport": "ssh"}

    monkeypatch.setattr(file_transfer_route.fts, "upload_stream", _fake_upload_stream)
    return captured


def test_upload_of_a_file_part_past_the_part_size_still_succeeds(
    authed_client, captured_upload
):
    """``max_part_size`` bounds text fields only, never a part with a filename.

    A cap that reached file parts would silently break every real upload over
    1MB, so this is the regression the new limits must not introduce.
    """
    payload = b"praxis-upload-payload" * 100_000  # ~2MB, past both spool and part size
    assert len(payload) > FORM_MAX_PART_SIZE

    res = authed_client.post(
        "/transfer/7/upload",
        params={"path": "/tmp/praxis-large-upload.bin"},
        files={"file": ("large.bin", payload, "application/octet-stream")},
    )
    assert res.status_code == 200, res.text
    assert res.json() == {
        "status": "success",
        "bytes": len(payload),
        "transport": "ssh",
    }
    assert captured_upload["body"] == payload
    assert captured_upload["local_filename"] == "large.bin"
