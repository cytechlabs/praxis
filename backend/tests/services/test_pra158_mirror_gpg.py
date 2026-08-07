"""PRA-158 slice #1: GPG helper tests.

Two layers:
  * Unit-level tests for ``ephemeral_gnupg_home`` and the fingerprint
    parser — these don't need a real ``gpg`` binary.
  * Integration tests that call real ``gpg`` to gen+import+verify; they
    skip when ``gpg`` is absent (hosted CI runner). Cold-rebuild's
    PRAXIS_REQUIRE_MIRROR_TOOL_TESTS=1 promotes the missing-binary
    case to a hard failure at module import (see test_pra157_real_subprocess).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services import mirror_gpg
from app.services.mirror_gpg import (
    MirrorGPGError,
    clearsign,
    detached_sign,
    ephemeral_gnupg_home,
    export_public_armored,
    export_secret_armored,
    generate_keypair,
    gpg_available,
    import_and_verify,
)

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)


# ---------------------------------------------------------------------------
# ephemeral_gnupg_home — pure unit tests, no gpg needed
# ---------------------------------------------------------------------------


def test_ephemeral_home_is_created_outside_mirror_data_and_wiped():
    captured: list[Path] = []
    with ephemeral_gnupg_home() as home:
        captured.append(home)
        assert home.exists()
        assert home.is_dir()
        # mode 0700: only owner has access
        assert (home.stat().st_mode & 0o777) == 0o700
        # OS-level invariant: the home is NOT under the locked
        # forbidden prefix (mirror data root).
        forbidden = Path("/data/praxis/mirrors").resolve()
        try:
            home.resolve().relative_to(forbidden)
            pytest.fail("ephemeral home landed under mirror data root")
        except ValueError:
            pass
    # After the with-block exits, the directory is gone.
    assert not captured[0].exists()


def test_ephemeral_home_is_wiped_on_exception():
    captured: list[Path] = []
    with pytest.raises(RuntimeError, match="boom"):
        with ephemeral_gnupg_home() as home:
            captured.append(home)
            assert home.exists()
            raise RuntimeError("boom")
    assert not captured[0].exists()


def test_ephemeral_home_default_forbidden_prefix_honors_mirror_root(
    monkeypatch, tmp_path
):
    """The default forbidden prefix must come from
    the configured ``PRAXIS_MIRROR_ROOT`` (via ``mirror_paths.mirror_root``),
    not a hard-coded path. An operator who relocates the volume must
    still get the TMPDIR-misconfig defense.

    Synthesis: point ``PRAXIS_MIRROR_ROOT`` at ``tmp_path``, force
    TMPDIR into the same dir, and confirm the default-args call refuses.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile as _tempfile

    _tempfile.tempdir = None  # reset cache

    try:
        with pytest.raises(MirrorGPGError, match="forbidden prefix"):
            with ephemeral_gnupg_home():
                pytest.fail("should have raised before yielding")
        leftover = list(tmp_path.glob("praxis-mirror-sign-*"))
        assert leftover == []
    finally:
        _tempfile.tempdir = None


def test_ephemeral_home_refuses_forbidden_prefix(tmp_path):
    """If TMPDIR points inside a forbidden prefix, abort fast.

    Synthesised by passing the tmp_path itself as the forbidden
    prefix: any home tempfile.mkdtemp opens under tmp_path will
    be inside it.
    """
    # Force tempfile to use tmp_path so the new home lands inside.
    old_tmp = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = str(tmp_path)
    try:
        import tempfile as _tempfile

        _tempfile.tempdir = None  # reset cache
        with pytest.raises(MirrorGPGError, match="forbidden prefix"):
            with ephemeral_gnupg_home(forbidden_prefixes=[tmp_path]):
                pytest.fail("should have raised before yielding")
        # The hostile home should still have been wiped before the raise.
        leftover = list(tmp_path.glob("praxis-mirror-sign-*"))
        assert leftover == []
    finally:
        if old_tmp is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_tmp
        import tempfile as _tempfile

        _tempfile.tempdir = None


# ---------------------------------------------------------------------------
# Real-gpg integration: gen → export → import → fingerprint match
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_generate_and_roundtrip_via_import():
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        assert len(fpr) == 40
        assert all(c in "0123456789ABCDEF" for c in fpr)
        public_a = export_public_armored(home, fpr)
        secret_a = export_secret_armored(home, fpr)
        assert "BEGIN PGP PUBLIC KEY BLOCK" in public_a
        assert "BEGIN PGP PRIVATE KEY BLOCK" in secret_a

    # Import into a brand-new home and verify fingerprint matches.
    with ephemeral_gnupg_home() as home2:
        import_and_verify(home2, secret_a, fpr)


@skip_without_gpg
def test_import_rejects_fingerprint_mismatch():
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        secret_a = export_secret_armored(home, fpr)

    bogus = "0" * 40
    with ephemeral_gnupg_home() as home2:
        with pytest.raises(MirrorGPGError, match="fingerprint mismatch"):
            import_and_verify(home2, secret_a, bogus)


@skip_without_gpg
def test_generate_keypair_rejects_invalid_slug():
    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="invalid slug"):
            generate_keypair(home, "Has Spaces")


def test_import_rejects_malformed_expected_fingerprint():
    """Pure-Python guard runs before any gpg invocation, so it
    doesn't need the binary.
    """
    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="40 hex chars"):
            import_and_verify(home, "irrelevant", "not-a-fingerprint")


def test_run_gpg_translates_missing_binary(monkeypatch):
    """If GPG_BIN points to a non-existent file, surface a clear error."""
    monkeypatch.setattr(mirror_gpg, "GPG_BIN", "/no/such/gpg-binary")
    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="not found"):
            export_public_armored(home, "A" * 40)


# ---------------------------------------------------------------------------
# PRA-158 #2a: clearsign + detached_sign primitives (real gpg)
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_clearsign_wraps_body_with_signature_block():
    body = b"Origin: Praxis\nLabel: Test\nSuite: stable\n"
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        signed = clearsign(home, fpr, body)
    text = signed.decode("utf-8")
    assert "-----BEGIN PGP SIGNED MESSAGE-----" in text
    assert "-----BEGIN PGP SIGNATURE-----" in text
    # The body must appear inline between the header and the
    # signature — that's the whole point of a clearsign.
    assert "Origin: Praxis" in text


@skip_without_gpg
def test_detached_sign_produces_armored_signature_only():
    body = b"some manifest bytes"
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        sig = detached_sign(home, fpr, body)
    text = sig.decode("utf-8")
    assert "-----BEGIN PGP SIGNATURE-----" in text
    assert "-----END PGP SIGNATURE-----" in text
    # Detached signature must NOT carry the signed body.
    assert "some manifest bytes" not in text


@skip_without_gpg
def test_detached_sign_verifies_against_body_with_gpg_verify():
    """Belt-and-suspenders: confirm gpg can verify what we just produced.
    Catches a future regression where we change flags in a way that
    silently produces an unverifiable artifact.
    """
    import subprocess

    body = b"verifiable body bytes\n"
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        sig = detached_sign(home, fpr, body)
        # Write both to disk and ask gpg to verify.
        body_path = home / "body.bin"
        sig_path = home / "body.sig"
        body_path.write_bytes(body)
        sig_path.write_bytes(sig)
        result = subprocess.run(
            ["gpg", "--homedir", str(home), "--verify", str(sig_path), str(body_path)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


@skip_without_gpg
def test_clearsign_verifies_against_inline_body():
    import subprocess

    body = b"clearsignable body\n"
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        signed = clearsign(home, fpr, body)
        signed_path = home / "InRelease"
        signed_path.write_bytes(signed)
        result = subprocess.run(
            ["gpg", "--homedir", str(home), "--verify", str(signed_path)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_clearsign_rejects_malformed_fingerprint():
    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="40 hex chars"):
            clearsign(home, "not-a-fingerprint", b"body")


def test_detached_sign_rejects_malformed_fingerprint():
    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="40 hex chars"):
            detached_sign(home, "short", b"body")
