"""PRA-160 slice #1: descriptor canonical-bytes serialization +
detached signature roundtrip.

GPG primitives are monkeypatched so the test runs without a real gpg
binary. Real-gpg integration coverage rides on
``test_pra158_mirror_gpg.py`` — the airgap signer reuses those
primitives, so we don't re-test them here.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import AirgapBundleSigningKey
from app.services.airgap import descriptor_signer as ds_module
from app.services.airgap.descriptor_signer import sign_and_write_descriptor
from app.services.airgap.schema import (
    BUNDLE_SCHEMA_VERSION,
    BundleDescriptor,
    ChannelDescriptor,
    ChannelRepoDescriptor,
    MirrorRunDescriptor,
    PayloadIndexEntry,
    ProfileDescriptor,
    deserialize_descriptor,
    serialize_descriptor,
)

_FPR = "AA00000000000000000000000000000000000001"


@pytest.fixture
def patch_gpg(monkeypatch):
    def fake_import_and_verify(home, armored, expected):
        # Strict to mirror the real primitive — mismatch raises.
        if expected != _FPR:
            raise AssertionError(f"unexpected fingerprint {expected}")

    def fake_detached_sign(home, fingerprint, body):
        # Non-trivial content so the on-disk file isn't empty.
        return b"-----BEGIN PGP SIGNATURE-----\nFAKE-SIG\n-----END-----\n"

    monkeypatch.setattr(
        ds_module.mirror_gpg, "import_and_verify", fake_import_and_verify
    )
    monkeypatch.setattr(ds_module.mirror_gpg, "detached_sign", fake_detached_sign)


@pytest.fixture
def descriptor() -> BundleDescriptor:
    return BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="11111111-1111-1111-1111-111111111111",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[
            ProfileDescriptor(
                slug="prod-base",
                display_name="Prod Base",
                package_family="deb",
                description=None,
                channel_slugs=["base"],
            )
        ],
        channels=[
            ChannelDescriptor(
                slug="base",
                display_name="Base",
                package_family="deb",
                description=None,
                repos=[
                    ChannelRepoDescriptor(
                        mirror_slug="ubuntu-jammy",
                        suite_override=None,
                        pinned_run_id=None,
                        pinned_manifest_sha256=None,
                    )
                ],
            )
        ],
        mirrors=[
            MirrorRunDescriptor(
                mirror_slug="ubuntu-jammy",
                package_family="deb",
                distribution="jammy",
                components=["main"],
                architectures=["amd64"],
                run_id=42,
                manifest_sha256="a" * 64,
                manifest_path="/data/praxis/mirrors/ubuntu-jammy/snapshots/42.manifest.json",
                byte_count=1024,
                package_count=8,
                signing_key_fingerprints=["BB" + "0" * 38],
                signing_keys_armored=["-----BEGIN PGP PUBLIC KEY BLOCK-----\n"],
            )
        ],
    )


@pytest.fixture
def signing_key_row():
    return AirgapBundleSigningKey(
        id=1,
        status="active",
        gpg_fingerprint=_FPR,
        key_uid=f"Praxis Airgap Bundle Signing {_FPR}",
        vault_path=f"praxis/bundle-signing-key/{_FPR}",
        armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
    )


def test_serialize_descriptor_is_canonical(descriptor):
    body = serialize_descriptor(descriptor)
    # Round-trip via Python json -> sort_keys=True normalises ordering.
    parsed = json.loads(body)
    re_canonicalized = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    assert re_canonicalized.encode("utf-8") == body
    # Spot-check fields.
    assert parsed["bundle_version"] == BUNDLE_SCHEMA_VERSION
    assert parsed["kind"] == "full"
    assert parsed["mirrors"][0]["mirror_slug"] == "ubuntu-jammy"


def test_deserialize_descriptor_round_trips(descriptor):
    body = serialize_descriptor(descriptor)
    parsed = deserialize_descriptor(body)
    assert parsed.bundle_id == descriptor.bundle_id
    assert parsed.profiles[0].slug == "prod-base"
    assert parsed.channels[0].repos[0].mirror_slug == "ubuntu-jammy"
    assert parsed.mirrors[0].run_id == 42


def test_deserialize_rejects_unknown_version():
    body = json.dumps(
        {
            "bundle_version": "v999",
            "bundle_id": "x",
            "kind": "full",
            "parent_bundle_id": None,
            "created_at": "2026-05-06T00:00:00Z",
            "praxis_instance_signing_fingerprint": _FPR,
            "profiles": [],
            "channels": [],
            "mirrors": [],
            "payload_index": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with pytest.raises(ValueError, match="unsupported bundle_version"):
        deserialize_descriptor(body)


def test_payload_index_round_trips_when_populated():
    desc = BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="abc",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[],
        channels=[],
        mirrors=[],
        payload_index=[
            PayloadIndexEntry(
                path_in_tar="mirrors/x/live/foo.deb",
                sha256="b" * 64,
                byte_count=128,
            )
        ],
    )
    body = serialize_descriptor(desc)
    parsed = deserialize_descriptor(body)
    assert parsed.payload_index[0].path_in_tar == "mirrors/x/live/foo.deb"


def test_sign_and_write_writes_files(
    tmp_path, monkeypatch, patch_gpg, descriptor, signing_key_row
):
    """Files land under the configured staging dir; bytes match what
    ``serialize_descriptor`` produced."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    body_path, sig_path = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="ignored-by-fake-gpg",
    )
    assert body_path.exists() and body_path.read_bytes() == serialize_descriptor(
        descriptor
    )
    assert sig_path.exists() and sig_path.read_bytes().startswith(
        b"-----BEGIN PGP SIGNATURE-----"
    )
    # Path is the staged-bundle path under the mirror root.
    assert ".airgap-staging" in str(body_path)
    assert descriptor.bundle_id in str(body_path)


def test_sign_overwrites_existing_descriptor(
    tmp_path, monkeypatch, patch_gpg, descriptor, signing_key_row
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    # Re-sign with a populated payload_index — slice #2 will rely on
    # this overwrite-in-place behavior.
    descriptor.payload_index = [
        PayloadIndexEntry(path_in_tar="payload/x", sha256="c" * 64, byte_count=42)
    ]
    body_path, _ = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    parsed = json.loads(body_path.read_bytes())
    assert parsed["payload_index"][0]["path_in_tar"] == "payload/x"


def test_atomic_pair_promotion_cleans_staging_siblings(
    tmp_path, monkeypatch, patch_gpg, descriptor, signing_key_row
):
    """Descriptor + signature land via .new/ → final
    rename so a crash mid-write or a concurrent reader never sees a
    half-written pair. After a successful sign:
      * final dir contains both files
      * sibling .new/ and .old/ dirs do NOT linger
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    body_path, sig_path = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    final_dir = body_path.parent
    new_sibling = final_dir.with_name(final_dir.name + ".new")
    old_sibling = final_dir.with_name(final_dir.name + ".old")
    assert body_path.exists()
    assert sig_path.exists()
    assert not new_sibling.exists(), f"stale .new sibling at {new_sibling}"
    assert not old_sibling.exists(), f"stale .old sibling at {old_sibling}"


def test_promotion_rollback_on_failed_second_rename(
    tmp_path, monkeypatch, patch_gpg, descriptor, signing_key_row
):
    """If os.rename(.new, final) fails after final →
    .old, move .old back to final before re-raising so a failed
    re-sign doesn't make the previously valid descriptor disappear."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    # First sign produces a valid pair.
    body_path, _ = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    final_dir = body_path.parent
    body_v1 = body_path.read_bytes()

    # Force the second rename (new → final) to fail by monkey-patching
    # os.rename to OSError on the .new path. Allow the first rename
    # (final → .old) to succeed so we exercise the rollback branch.
    import os as os_mod

    real_rename = os_mod.rename
    new_dir = final_dir.with_name(final_dir.name + ".new")

    def bad_rename(src, dst):
        if str(src).endswith(new_dir.name):
            raise OSError("simulated promotion failure")
        return real_rename(src, dst)

    from app.services.airgap import descriptor_signer as ds_module

    monkeypatch.setattr(ds_module.os, "rename", bad_rename)

    descriptor.payload_index = [
        PayloadIndexEntry(path_in_tar="payload/y", sha256="d" * 64, byte_count=99)
    ]
    with pytest.raises(OSError, match="simulated promotion failure"):
        sign_and_write_descriptor(
            descriptor=descriptor,
            signing_key=signing_key_row,
            private_armored="x",
        )

    # Rollback restored the prior descriptor at the canonical path.
    assert final_dir.exists()
    assert body_path.exists()
    assert body_path.read_bytes() == body_v1
    # No half-promoted .new dir lingers; the .old dir is gone too
    # (rolled back into final).
    old_dir = final_dir.with_name(final_dir.name + ".old")
    assert not old_dir.exists()


def test_atomic_pair_resign_replaces_old_pair_atomically(
    tmp_path, monkeypatch, patch_gpg, descriptor, signing_key_row
):
    """Re-sign with a new descriptor body must replace BOTH files;
    an observer never sees old body + new sig or vice versa. We
    verify by reading both files immediately after the second sign:
    the body bytes must match the second canonical serialization
    AND the .sig file must exist."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    body_path, sig_path = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    body_v1 = body_path.read_bytes()
    sig_v1 = sig_path.read_bytes()

    # Mutate descriptor and re-sign.
    descriptor.payload_index = [
        PayloadIndexEntry(
            path_in_tar="mirrors/y/live/bar.deb",
            sha256="d" * 64,
            byte_count=256,
        )
    ]
    from app.services.airgap.schema import serialize_descriptor as _ser

    expected_v2_body = _ser(descriptor)
    body_path2, sig_path2 = sign_and_write_descriptor(
        descriptor=descriptor,
        signing_key=signing_key_row,
        private_armored="x",
    )
    body_v2 = body_path2.read_bytes()
    sig_v2 = sig_path2.read_bytes()

    assert body_v2 == expected_v2_body
    assert body_v2 != body_v1
    # Sig is a fake-bytes string in the test, but its presence is the
    # invariant: the file must exist alongside the new body.
    assert sig_v2 == sig_v1  # fake gpg returns same bytes
    # No staging siblings linger after promotion.
    final_dir = body_path2.parent
    assert not final_dir.with_name(final_dir.name + ".new").exists()
    assert not final_dir.with_name(final_dir.name + ".old").exists()
