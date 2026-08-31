"""PRA-426: /health reports the version of the artifact that is running.

The version was a literal in ``create_app``, so it kept reporting the previous
release until somebody remembered to edit it. These tests pin the replacement:
the installed package's metadata is the authority, an explicit deployment
override is honored only when it is a well-formed release version, and a tree
whose package was never installed is labelled rather than passed off as a
release.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from importlib.metadata import PackageNotFoundError
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.core import version as version_module

SETUP_PY = Path(__file__).resolve().parents[2] / "setup.py"

# Same shape the release index accepts.
RELEASE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}(?:-[0-9A-Za-z.-]+)?$"
)


def _packaged_version() -> str:
    """The release version declared by the backend package, read from source."""
    match = re.search(r'version\s*=\s*"([^"]+)"', SETUP_PY.read_text(encoding="utf-8"))
    assert match, f"no version declared in {SETUP_PY}"
    return match.group(1)


def _health_version(app_instance) -> str:
    # No lifespan: this exercises the route, not application startup.
    res = TestClient(app_instance).get("/health")
    assert res.status_code == 200, res.text
    return res.json()["version"]


# ------------------------------------------------------------------ the endpoint


def test_health_reports_the_packaged_release_version(client):
    """The endpoint must agree with the package the image was built from.

    Requires the backend package to be installed, exactly as CI and the
    production image install it.
    """
    body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["version"] == _packaged_version()


def test_health_follows_the_package_metadata_rather_than_a_literal(monkeypatch):
    """Drive the authority to a version no file in the tree contains. A literal
    left behind anywhere on this path would keep reporting the real one."""
    monkeypatch.delenv(version_module.OVERRIDE_ENV_VAR, raising=False)
    monkeypatch.setattr(
        version_module, "distribution_version", lambda name: "9.9.9-rc.1"
    )
    assert _health_version(create_app()) == "9.9.9-rc.1"


def test_health_labels_an_uninstalled_tree_instead_of_claiming_a_release(monkeypatch):
    def _missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.delenv(version_module.OVERRIDE_ENV_VAR, raising=False)
    monkeypatch.setattr(version_module, "distribution_version", _missing)
    reported = _health_version(create_app())
    assert reported == version_module.UNKNOWN_VERSION
    assert not RELEASE_VERSION_RE.fullmatch(reported)


def test_openapi_document_reports_the_same_version(client):
    """The published schema and the health endpoint describe one artifact."""
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == client.get("/health").json()["version"]


def test_support_bundle_reports_the_same_version(db, client, admin_user):
    """The support bundle used to carry its own copy of the literal."""
    login = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert login.status_code == 200, login.text
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    res = client.post("/diagnostics/bundle?time_range=24h")
    assert res.status_code == 200, res.text
    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        reported = json.loads(zf.read("version.json"))["praxis_version"]
    assert reported == client.get("/health").json()["version"]


# ------------------------------------------------------------------- the source


def test_installed_metadata_is_the_authority(monkeypatch):
    monkeypatch.delenv(version_module.OVERRIDE_ENV_VAR, raising=False)
    monkeypatch.setattr(version_module, "distribution_version", lambda name: "4.5.6")
    assert version_module.get_version() == "4.5.6"


def test_deployment_override_is_honored_with_or_without_the_tag_prefix(monkeypatch):
    monkeypatch.setattr(version_module, "distribution_version", lambda name: "4.5.6")
    for raw, expected in (
        ("1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        (" 1.2.3 ", "1.2.3"),
    ):
        monkeypatch.setenv(version_module.OVERRIDE_ENV_VAR, raw)
        assert version_module.get_version() == expected


def test_a_malformed_override_falls_back_to_the_package(monkeypatch):
    """The variable also names image tags, so it can hold values that are not a
    release version. Reporting one verbatim would let any string become the
    product version."""
    monkeypatch.setattr(version_module, "distribution_version", lambda name: "4.5.6")
    for raw in ("latest", "1.0", "1.0.0.1", "v", "1.0.0 (build 7)", "01.0.0", "  "):
        monkeypatch.setenv(version_module.OVERRIDE_ENV_VAR, raw)
        assert version_module.get_version() == "4.5.6", raw


def test_a_malformed_override_cannot_stand_in_for_missing_metadata(monkeypatch):
    def _missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.setattr(version_module, "distribution_version", _missing)
    monkeypatch.setenv(version_module.OVERRIDE_ENV_VAR, "latest")
    assert version_module.get_version() == version_module.UNKNOWN_VERSION


def test_an_empty_override_is_not_treated_as_a_version(monkeypatch):
    monkeypatch.setattr(version_module, "distribution_version", lambda name: "4.5.6")
    monkeypatch.setenv(version_module.OVERRIDE_ENV_VAR, "")
    assert version_module.get_version() == "4.5.6"
