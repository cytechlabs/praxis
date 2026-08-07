"""PRA-159 #3: channel_source_writer unit tests (pure function)."""

from __future__ import annotations

import pytest

from app.services.channel_source_writer import (
    BASIC_AUTH_USERNAME,
    DEB_AUTH_DIR,
    DEB_SOURCES_DIR,
    MANAGED_FILENAME_PREFIX,
    RPM_REPOS_DIR,
    compute_source_files,
    managed_directories,
    managed_filenames,
)
from app.services.content_profile_service import ResolvedMirrorEntry


def _entry(
    *,
    mirror_id=1,
    mirror_slug="ubuntu-jammy",
    suite="jammy",
    components=None,
    architectures=None,
    package_family="deb",
    pinned_run_id=None,
    pinned_manifest_sha256=None,
    channel_id=10,
    channel_slug="prod-base",
):
    return ResolvedMirrorEntry(
        channel_id=channel_id,
        channel_slug=channel_slug,
        mirror_id=mirror_id,
        mirror_slug=mirror_slug,
        package_family=package_family,
        suite=suite,
        components=components or ["main", "universe"],
        architectures=architectures or ["amd64"],
        pinned_run_id=pinned_run_id,
        pinned_manifest_sha256=pinned_manifest_sha256,
    )


# ---------------------------------------------------------------------------
# deb
# ---------------------------------------------------------------------------


def test_deb_emits_two_files_with_expected_paths():
    files = compute_source_files(
        profile_slug="prod-deb",
        package_family="deb",
        entries=[_entry()],
        serve_credentials={1: "tok-aaaa"},
        serve_base_url="https://praxis.example.com",
    )
    paths = [f.path for f in files]
    assert paths == [
        f"{DEB_SOURCES_DIR}/{MANAGED_FILENAME_PREFIX}prod-deb.list",
        f"{DEB_AUTH_DIR}/{MANAGED_FILENAME_PREFIX}prod-deb.conf",
    ]
    modes = {f.path: f.mode for f in files}
    assert modes[paths[0]] == "0644"
    assert modes[paths[1]] == "0600"  # contains creds


def test_deb_sources_body_uses_signed_by_and_no_secrets():
    files = compute_source_files(
        profile_slug="prod-deb",
        package_family="deb",
        entries=[_entry()],
        serve_credentials={1: "tok-secret-do-not-leak"},
        serve_base_url="https://praxis.example.com",
    )
    sources_body = files[0].body.decode("utf-8")
    assert (
        "deb [signed-by=/etc/apt/keyrings/praxis-mirror-ubuntu-jammy.asc]"
        in sources_body
    )
    assert "https://praxis.example.com/mirrors/ubuntu-jammy/serve" in sources_body
    assert "jammy main universe" in sources_body
    # CRITICAL: secret never appears in the world-readable .list file.
    assert "tok-secret-do-not-leak" not in sources_body


def test_deb_auth_body_carries_creds_with_praxis_username():
    files = compute_source_files(
        profile_slug="prod-deb",
        package_family="deb",
        entries=[_entry()],
        serve_credentials={1: "tok-secret"},
        serve_base_url="https://praxis.example.com",
    )
    auth_body = files[1].body.decode("utf-8")
    assert "machine praxis.example.com/mirrors/ubuntu-jammy/serve" in auth_body
    assert f"login {BASIC_AUTH_USERNAME}" in auth_body
    assert "password tok-secret" in auth_body


def test_deb_multi_suite_composition_renders_one_line_per_entry():
    """A profile composing jammy + jammy-security + jammy-updates of
    one mirror should emit three deb lines."""
    entries = [
        _entry(suite="jammy"),
        _entry(suite="jammy-security"),
        _entry(suite="jammy-updates"),
    ]
    files = compute_source_files(
        profile_slug="prod-deb",
        package_family="deb",
        entries=entries,
        serve_credentials={1: "tok"},
        serve_base_url="https://x.com",
    )
    sources = files[0].body.decode("utf-8")
    assert sources.count("deb [signed-by=") == 3
    for suite in ("jammy", "jammy-security", "jammy-updates"):
        assert f" {suite} " in sources


def test_deb_auth_block_dedups_per_mirror_across_suites():
    """Multi-suite composition of one mirror produces N source
    lines but only ONE machine block in auth.conf."""
    entries = [
        _entry(suite="jammy"),
        _entry(suite="jammy-security"),
        _entry(suite="jammy-updates"),
    ]
    files = compute_source_files(
        profile_slug="prod-deb",
        package_family="deb",
        entries=entries,
        serve_credentials={1: "tok-shared"},
        serve_base_url="https://praxis.example.com",
    )
    sources = files[0].body.decode("utf-8")
    auth = files[1].body.decode("utf-8")
    assert sources.count("deb [signed-by=") == 3
    # One machine block, not three.
    assert auth.count("machine ") == 1
    assert auth.count("password tok-shared") == 1


def test_deb_components_default_main_when_empty():
    files = compute_source_files(
        profile_slug="empty-comp",
        package_family="deb",
        entries=[_entry(components=[])],
        serve_credentials={1: "tok"},
        serve_base_url="https://x.com",
    )
    sources = files[0].body.decode("utf-8")
    # Default to `main` so apt parses cleanly when the mirror has
    # no components (rare but legal — flat repo).
    assert " jammy main" in sources


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------


def test_rpm_emits_one_file_at_0600():
    files = compute_source_files(
        profile_slug="prod-rpm",
        package_family="rpm",
        entries=[_entry(package_family="rpm", mirror_slug="rocky-9", suite="9")],
        serve_credentials={1: "tok-rpm"},
        serve_base_url="https://praxis.example.com",
        key_fingerprints_by_mirror_id={1: ["AAAAAAAA1111111111"]},
    )
    assert len(files) == 1
    assert files[0].path == f"{RPM_REPOS_DIR}/{MANAGED_FILENAME_PREFIX}prod-rpm.repo"
    assert files[0].mode == "0600"


def test_rpm_repo_body_carries_creds_inline():
    files = compute_source_files(
        profile_slug="prod-rpm",
        package_family="rpm",
        entries=[_entry(package_family="rpm", mirror_slug="rocky-9", suite="9")],
        serve_credentials={1: "tok-rpm-secret"},
        serve_base_url="https://praxis.example.com",
        key_fingerprints_by_mirror_id={1: ["abcdef1234567890"]},
    )
    body = files[0].body.decode("utf-8")
    assert "[praxis-prod-rpm-rocky-9]" in body
    assert "baseurl=https://praxis.example.com/mirrors/rocky-9/serve" in body
    assert "gpgcheck=1" in body
    # Explicit per-fingerprint URL — NOT a wildcard glob.
    assert (
        "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-rocky-9-abcdef12"
        in body
    )
    assert "username=praxis" in body
    assert "password=tok-rpm-secret" in body


def test_rpm_repo_body_emits_one_gpgkey_per_fingerprint():
    """Multiple bundle keys (active + pending_cutover) yield
    multi-value gpgkey via whitespace continuation."""
    files = compute_source_files(
        profile_slug="prod-rpm",
        package_family="rpm",
        entries=[_entry(package_family="rpm", mirror_slug="rocky-9", suite="9")],
        serve_credentials={1: "tok"},
        serve_base_url="https://x.com",
        key_fingerprints_by_mirror_id={1: ["AAAAAAAA1111111111", "BBBBBBBB2222222222"]},
    )
    body = files[0].body.decode("utf-8")
    assert "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-rocky-9-aaaaaaaa" in body
    assert "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-rocky-9-bbbbbbbb" in body


def test_rpm_missing_fingerprints_raises():
    with pytest.raises(KeyError, match="fingerprints"):
        compute_source_files(
            profile_slug="x",
            package_family="rpm",
            entries=[_entry(package_family="rpm", mirror_slug="rocky-9", suite="9")],
            serve_credentials={1: "tok"},
            serve_base_url="https://x.com",
            key_fingerprints_by_mirror_id={},
        )


def test_rpm_empty_fingerprint_list_raises():
    with pytest.raises(KeyError, match="fingerprints"):
        compute_source_files(
            profile_slug="x",
            package_family="rpm",
            entries=[_entry(package_family="rpm", mirror_slug="rocky-9", suite="9")],
            serve_credentials={1: "tok"},
            serve_base_url="https://x.com",
            key_fingerprints_by_mirror_id={1: []},
        )


def test_rpm_dedups_stanza_per_mirror_id():
    """Multi-entry input for the SAME mirror collapses to one rpm
    stanza: rpm baseurl is one URL per stanza so
    duplicates would be ambiguous / invalid."""
    entries = [
        _entry(mirror_id=1, mirror_slug="rocky-9", package_family="rpm", suite="9"),
        _entry(
            mirror_id=1,
            mirror_slug="rocky-9",
            package_family="rpm",
            suite="9-extras",
        ),
    ]
    files = compute_source_files(
        profile_slug="prod-rpm",
        package_family="rpm",
        entries=entries,
        serve_credentials={1: "tok"},
        serve_base_url="https://x.com",
        key_fingerprints_by_mirror_id={1: ["A" * 40]},
    )
    body = files[0].body.decode("utf-8")
    assert body.count("[praxis-prod-rpm-rocky-9]") == 1


def test_rpm_multi_mirror_emits_multi_stanza():
    entries = [
        _entry(
            mirror_id=1, mirror_slug="rocky-9-base", package_family="rpm", suite="9"
        ),
        _entry(
            mirror_id=2,
            mirror_slug="rocky-9-extras",
            package_family="rpm",
            suite="9",
        ),
    ]
    files = compute_source_files(
        profile_slug="prod-rpm",
        package_family="rpm",
        entries=entries,
        serve_credentials={1: "tok-1", 2: "tok-2"},
        serve_base_url="https://x.com",
        key_fingerprints_by_mirror_id={
            1: ["AAAAAAAA1111111111"],
            2: ["BBBBBBBB2222222222"],
        },
    )
    body = files[0].body.decode("utf-8")
    assert body.count("[praxis-prod-rpm-") == 2
    assert "[praxis-prod-rpm-rocky-9-base]" in body
    assert "[praxis-prod-rpm-rocky-9-extras]" in body
    assert "tok-1" in body
    assert "tok-2" in body


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def test_empty_entries_returns_empty_list():
    """A no_profile / conflict resolution shouldn't ever reach this
    code path, but if it does, return [] cleanly so the orchestrator
    handles the no-managed-files case without a crash."""
    assert (
        compute_source_files(
            profile_slug="x",
            package_family="deb",
            entries=[],
            serve_credentials={},
            serve_base_url="https://x.com",
        )
        == []
    )


def test_unsupported_package_family_raises():
    with pytest.raises(ValueError, match="package_family"):
        compute_source_files(
            profile_slug="x",
            package_family="snap",
            entries=[_entry()],
            serve_credentials={1: "tok"},
            serve_base_url="https://x.com",
        )


def test_missing_credential_raises_loud():
    """A forgotten cred issue should surface as KeyError so the
    orchestrator's apply path bails loud, not as a half-config."""
    with pytest.raises(KeyError):
        compute_source_files(
            profile_slug="x",
            package_family="deb",
            entries=[_entry(mirror_id=1)],
            serve_credentials={},  # missing!
            serve_base_url="https://x.com",
        )


def test_managed_directories_per_family():
    assert managed_directories("deb") == [DEB_SOURCES_DIR, DEB_AUTH_DIR]
    assert managed_directories("rpm") == [RPM_REPOS_DIR]


def test_managed_filenames_per_family():
    assert sorted(managed_filenames("prod", "deb")) == sorted(
        [
            f"{MANAGED_FILENAME_PREFIX}prod.list",
            f"{MANAGED_FILENAME_PREFIX}prod.conf",
        ]
    )
    assert managed_filenames("prod", "rpm") == [f"{MANAGED_FILENAME_PREFIX}prod.repo"]


def test_managed_filename_prefix_locked():
    # Lock check: the prefix must remain ``praxis-profile-`` so the
    # apply orchestrator's diff step matches the same thing the
    # source writer produces.
    assert MANAGED_FILENAME_PREFIX == "praxis-profile-"
