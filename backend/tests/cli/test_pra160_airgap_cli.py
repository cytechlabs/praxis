"""PRA-160 slice #5: praxis-airgap CLI tests.

Builds a real tar via the slice-#2 export pipeline (faked GPG)
then exercises ``inspect`` / ``verify`` on the resulting file.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.cli import airgap as cli_module
from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from app.services.airgap import descriptor_signer as ds_module
from app.services.airgap import signing_key_service as sk_module
from app.services.airgap.orchestrator import AirgapExportOrchestrator
from tests.helpers.armor import pgp_private_block

_FPR = "AB00000000000000000000000000000000000001"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Fake GPG primitives across export and CLI verify paths."""

    def fake_generate(home, slug):
        return _FPR

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-PRIV-{fpr}")

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    def fake_import_and_verify(home, armored, expected):
        if expected != _FPR:
            raise AssertionError(f"unexpected fingerprint {expected}")

    def fake_detached_sign(home, fingerprint, body):
        return b"-----BEGIN PGP SIGNATURE-----\nFAKE-SIG\n-----END-----\n"

    def fake_import_public(home, armored):
        return None

    def fake_verify_detached(home, sig_path, body_path):
        # Signal "fail" by raising MirrorGPGError when key file
        # contains a "BAD" marker; otherwise pass.
        text = (home / "pubring.kbx").exists() and ""  # no-op
        # We can't read the keyring contents, so use a sentinel
        # written into ``body`` from the test layer instead. Tests
        # control pass/fail by the key file they supply, and this
        # fake delegates to the cli_module.mirror_gpg patches set
        # on a per-test basis below.
        return None

    monkeypatch.setattr(sk_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        sk_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        sk_module.mirror_gpg, "export_public_armored", fake_export_public
    )
    monkeypatch.setattr(
        ds_module.mirror_gpg, "import_and_verify", fake_import_and_verify
    )
    monkeypatch.setattr(ds_module.mirror_gpg, "detached_sign", fake_detached_sign)
    monkeypatch.setattr(
        cli_module.mirror_gpg, "import_armored_public", fake_import_public
    )
    monkeypatch.setattr(cli_module.mirror_gpg, "verify_detached", fake_verify_detached)


def _seed_export_side(db) -> tuple[str, MirrorSyncRun]:
    mirror = MirrorRepo(
        slug="ubuntu-jammy",
        display_name="Ubuntu Jammy",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="ok",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.commit()
    db.refresh(mirror)
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow() + timedelta(seconds=5),
        status="ok",
        run_kind="sync",
        byte_count=4096,
        package_count=12,
        manifest_sha256="a" * 64,
        manifest_path=f"/snapshots/run-{mirror.id}.manifest.json",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    profile = ContentProfile(
        slug="prod-base", display_name="prod-base", package_family="deb"
    )
    channel = ContentChannel(slug="base", display_name="base", package_family="deb")
    db.add(profile)
    db.add(channel)
    db.commit()
    db.refresh(profile)
    db.refresh(channel)
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(ContentChannelRepo(channel_id=channel.id, mirror_id=mirror.id))
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="active",
            gpg_fingerprint="DD" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {mirror.slug}",
            vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/DD" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    db.commit()
    return "ubuntu-jammy", run


def _seed_export_disk(mirror_root: Path, slug: str, run_id: int) -> None:
    mirror_dir = mirror_root / slug
    snaps = mirror_dir / "snapshots"
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / f"{run_id}.manifest.json").write_bytes(b'{"manifest_sha256":"a"}')
    (snaps / f"{run_id}.manifest.json.sig").write_bytes(
        b"-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END-----\n"
    )
    live = mirror_dir / "live"
    live.mkdir(parents=True, exist_ok=True)
    (live / "Release").write_bytes(b"Suite: jammy\n")


def _build_bundle(db, tmp_path: Path) -> Path:
    slug, run = _seed_export_side(db)
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    import os

    os.environ["PRAXIS_MIRROR_ROOT"] = str(mirror_root)
    os.environ["PRAXIS_AIRGAP_BUNDLE_ROOT"] = str(bundle_root)
    _seed_export_disk(mirror_root, slug, run.id)
    orch = AirgapExportOrchestrator(db)
    row = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    built = orch.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)
    return Path(built.bundle_path)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def test_inspect_prints_descriptor(db, mock_vault, patch_gpg, tmp_path, capsys):
    bundle_path = _build_bundle(db, tmp_path)
    rc = cli_module.main(["inspect", str(bundle_path)])
    assert rc == cli_module.EXIT_OK
    out = capsys.readouterr()
    # Pretty-printed JSON contains the bundle_id from the descriptor.
    assert '"bundle_id":' in out.out
    assert "ubuntu-jammy" in out.out
    # Summary line goes to stderr.
    assert "kind=full" in out.err


def test_inspect_missing_tar_returns_io_error(tmp_path, capsys):
    rc = cli_module.main(["inspect", str(tmp_path / "nope.tar")])
    assert rc == cli_module.EXIT_IO_ERROR
    assert "not found" in capsys.readouterr().err


def test_inspect_corrupt_tar_returns_io_error(tmp_path, capsys):
    bad = tmp_path / "garbage.tar"
    bad.write_bytes(b"not a tar at all")
    rc = cli_module.main(["inspect", str(bad)])
    assert rc == cli_module.EXIT_IO_ERROR


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_pass(db, mock_vault, patch_gpg, tmp_path, capsys):
    bundle_path = _build_bundle(db, tmp_path)
    keyfile = tmp_path / "exporter-pub.asc"
    keyfile.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n")
    rc = cli_module.main(["verify", str(bundle_path), "--key-file", str(keyfile)])
    assert rc == cli_module.EXIT_OK
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "bundle_id=" in out
    assert "kind=full" in out


def test_verify_fail_with_wrong_key(
    db, mock_vault, patch_gpg, tmp_path, capsys, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    keyfile = tmp_path / "wrong-pub.asc"
    keyfile.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nWRONG\n-----END-----\n")

    # Force verify_detached to raise MirrorGPGError.
    def fake_verify_detached(home, sig_path, body_path):
        raise cli_module.mirror_gpg.MirrorGPGError("simulated bad signature")

    monkeypatch.setattr(cli_module.mirror_gpg, "verify_detached", fake_verify_detached)

    rc = cli_module.main(["verify", str(bundle_path), "--key-file", str(keyfile)])
    assert rc == cli_module.EXIT_VERIFY_FAILED
    assert "FAIL" in capsys.readouterr().err


def test_verify_missing_key_file(tmp_path, capsys):
    bundle = tmp_path / "x.tar"
    bundle.write_bytes(b"ignored")
    rc = cli_module.main(
        ["verify", str(bundle), "--key-file", str(tmp_path / "nope.asc")]
    )
    assert rc == cli_module.EXIT_BAD_ARGS
    assert "key file not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# argparse → EXIT_BAD_ARGS
# ---------------------------------------------------------------------------


def test_no_subcommand_returns_bad_args(capsys):
    """Calling the CLI with no subcommand must surface
    EXIT_BAD_ARGS (3), not argparse's default sys.exit(2) (which
    collides with our documented EXIT_VERIFY_FAILED)."""
    with pytest.raises(SystemExit) as excinfo:
        cli_module.main([])
    assert excinfo.value.code == cli_module.EXIT_BAD_ARGS


def test_unknown_subcommand_returns_bad_args(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["frobnicate"])
    assert excinfo.value.code == cli_module.EXIT_BAD_ARGS


def test_verify_missing_key_file_flag_returns_bad_args(tmp_path, capsys):
    """``verify`` without ``--key-file`` is an argparse error and must
    surface EXIT_BAD_ARGS, not collide with EXIT_VERIFY_FAILED."""
    bundle = tmp_path / "x.tar"
    bundle.write_bytes(b"ignored")
    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["verify", str(bundle)])
    assert excinfo.value.code == cli_module.EXIT_BAD_ARGS


def test_unknown_option_returns_bad_args(tmp_path, capsys):
    bundle = tmp_path / "x.tar"
    bundle.write_bytes(b"ignored")
    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["inspect", str(bundle), "--no-such-option"])
    assert excinfo.value.code == cli_module.EXIT_BAD_ARGS


# ---------------------------------------------------------------------------
# EXIT_UNSUPPORTED_VERSION
# ---------------------------------------------------------------------------


def _make_tar_with_descriptor(tar_path: Path, body: bytes, sig: bytes) -> None:
    """Build a minimal tar containing only the descriptor pair so we
    can exercise the version-rejection path without standing up the
    full export pipeline."""
    import io
    import tarfile

    with tarfile.open(tar_path, mode="w") as tar:
        for name, payload in (("bundle.json", body), ("bundle.json.sig", sig)):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


def test_inspect_future_bundle_version_returns_unsupported_version(tmp_path, capsys):
    """A descriptor with a future ``bundle_version`` must exit with
    EXIT_UNSUPPORTED_VERSION (5), not the generic EXIT_IO_ERROR.
    Future version strings are how a newer Praxis exporter signals
    "your importer is too old"."""
    body = b'{"bundle_version": "v999", "bundle_id": "x"}'
    sig = b"sig"
    tar = tmp_path / "future.tar"
    _make_tar_with_descriptor(tar, body, sig)
    rc = cli_module.main(["inspect", str(tar)])
    assert rc == cli_module.EXIT_UNSUPPORTED_VERSION
    err = capsys.readouterr().err
    assert "newer Praxis" in err


# ---------------------------------------------------------------------------
# Malformed descriptor → EXIT_IO_ERROR
# ---------------------------------------------------------------------------


def test_inspect_malformed_descriptor_missing_field_returns_io_error(tmp_path, capsys):
    """A descriptor with the right bundle_version but missing
    required fields raises KeyError out of deserialize_descriptor.
    The CLI must catch it and surface EXIT_IO_ERROR rather than
    leaking a Python traceback to the operator."""
    # Right version, but no profiles/channels/mirrors/etc.
    body = b'{"bundle_version": "v1", "bundle_id": "x"}'
    sig = b"sig"
    tar = tmp_path / "missing-field.tar"
    _make_tar_with_descriptor(tar, body, sig)
    rc = cli_module.main(["inspect", str(tar)])
    assert rc == cli_module.EXIT_IO_ERROR
    err = capsys.readouterr().err
    assert "descriptor unreadable" in err


def test_inspect_malformed_descriptor_wrong_shape_returns_io_error(tmp_path, capsys):
    """A descriptor where ``profiles`` is the wrong shape (string
    instead of list of dicts) raises TypeError out of the
    ``ProfileDescriptor(**p)`` expansion. Same EXIT_IO_ERROR
    surface — no traceback."""
    body = (
        b'{"bundle_version": "v1", "bundle_id": "x", '
        b'"profiles": "not-a-list", "channels": [], "mirrors": []}'
    )
    sig = b"sig"
    tar = tmp_path / "wrong-shape.tar"
    _make_tar_with_descriptor(tar, body, sig)
    rc = cli_module.main(["inspect", str(tar)])
    assert rc == cli_module.EXIT_IO_ERROR


def test_inspect_invalid_json_descriptor_returns_io_error(tmp_path, capsys):
    """A descriptor that isn't valid JSON raises ValueError from
    json.loads inside deserialize_descriptor. Same EXIT_IO_ERROR
    surface."""
    body = b"not json at all }{"
    sig = b"sig"
    tar = tmp_path / "bad-json.tar"
    _make_tar_with_descriptor(tar, body, sig)
    rc = cli_module.main(["inspect", str(tar)])
    assert rc == cli_module.EXIT_IO_ERROR


def test_verify_malformed_descriptor_after_sig_success_returns_ok_with_warn(
    tmp_path, capsys, monkeypatch
):
    """If the signature verifies but the body itself is malformed,
    surface PASS with a WARN tag — operator's pinned key was right
    even though the descriptor is shape-broken. Returns EXIT_OK,
    not EXIT_IO_ERROR, so scripts that gate on "key recognized
    this bundle" still see success."""
    body = b'{"bundle_version": "v1", "bundle_id": "x"}'  # missing fields
    sig = b"sig"
    tar = tmp_path / "verified-but-malformed.tar"
    _make_tar_with_descriptor(tar, body, sig)
    keyfile = tmp_path / "pub.asc"
    keyfile.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n")

    # Stub mirror_gpg primitives so verify_detached succeeds.
    monkeypatch.setattr(
        cli_module.mirror_gpg, "import_armored_public", lambda home, armored: None
    )
    monkeypatch.setattr(
        cli_module.mirror_gpg, "verify_detached", lambda home, sp, bp: None
    )

    rc = cli_module.main(["verify", str(tar), "--key-file", str(keyfile)])
    assert rc == cli_module.EXIT_OK
    err = capsys.readouterr().err
    assert "WARN" in err
    assert "descriptor body can't be parsed" in err


# ---------------------------------------------------------------------------
# console-script entry point
# ---------------------------------------------------------------------------


def test_console_script_entry_point_registered():
    """The ``praxis-airgap`` console-script entry point in setup.py
    must resolve to ``app.cli.airgap.main``. We don't shell out (the
    binary may not be on PATH inside pytest depending on how the
    package was installed); we read setup.py and confirm the
    entry-point declaration is in place so the Dockerfile's
    ``pip install -e .`` step puts the binary on PATH."""
    import re
    from pathlib import Path as _Path

    setup_text = (_Path(__file__).resolve().parents[2] / "setup.py").read_text(
        encoding="utf-8"
    )
    assert re.search(
        r"praxis-airgap\s*=\s*app\.cli\.airgap:main", setup_text
    ), "praxis-airgap console_scripts entry point is missing from setup.py"
