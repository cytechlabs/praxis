"""GPG primitives for the mirror signing pipeline (PRA-158 slice #1).

Wraps subprocess calls to ``gpg`` so the rest of the codebase never
touches raw process plumbing or environment variables. Two callers are
expected:

  * ``MirrorSigningKeyService`` (slice #1): generate keypair, export
    armored private + public for Vault storage.
  * ``SigningEngine`` (slice #2): import the private key from Vault into
    an ephemeral home, sign artifacts, throw the home away.

Locks (project_pra158_design_locks.md "Secret boundary"):
  * Every gpg invocation that touches private material runs under an
    ephemeral GNUPGHOME built fresh in a tempdir OUTSIDE ``work/``,
    ``live/``, ``snapshots/``, and ``snapshots-staging/``.
  * The home is mode 0700 and is wiped via ``shutil.rmtree`` in a
    ``finally`` block — even on exception, even on signal-induced
    interpreter exit.
  * Imported private keys MUST be verified to match the expected
    fingerprint before any signing occurs. Mismatch raises and aborts;
    NEVER logs key material, NEVER logs the GNUPGHOME contents.
  * Public keys are not secrets; they may be cached, written to disk
    artifacts, and surfaced through API endpoints. Private keys never
    leave Vault except into an ephemeral GNUPGHOME and never back to a
    persistent location.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# GPG binary name — overridable for tests but defaults to PATH lookup.
GPG_BIN = "gpg"

# Subprocess timeouts in seconds. Generation is the slow path
# (entropy-bound on first 4096-bit key); other ops are quick.
_GPG_GEN_TIMEOUT_S = 600
_GPG_OP_TIMEOUT_S = 60

# Tempdir prefix — chosen so a ``ps``/``ls`` glance makes it obvious
# what these dirs are and which subsystem owns them. Cleanup audits can
# grep this prefix.
_GNUPG_HOME_PREFIX = "praxis-mirror-sign-"

_FPR_RE = re.compile(r"^fpr:::::::::([A-F0-9]{40}):", re.MULTILINE)
# Each ``pub:`` colon-format line indicates one primary public key.
# Used to detect multi-primary armored bodies (a
# single PGP PUBLIC KEY BLOCK can pack multiple primary keys; one
# armor header is not the same as one key).
_PUB_RE = re.compile(r"^pub:", re.MULTILINE)


class MirrorGPGError(RuntimeError):
    """Raised on any gpg invocation or fingerprint-verification failure.

    Error messages NEVER carry key material or GNUPGHOME contents —
    only structured fields the operator needs to diagnose (binary
    name, return code, fingerprint expected vs observed).
    """


def gpg_available() -> bool:
    """Return True iff the ``gpg`` binary is on PATH.

    Slice #1's preflight check uses this to decide whether to skip
    integration tests on hosted CI; cold-rebuild fails hard via the
    PRAXIS_REQUIRE_MIRROR_TOOL_TESTS gate.
    """
    return shutil.which(GPG_BIN) is not None


@contextmanager
def ephemeral_gnupg_home(
    forbidden_prefixes: Optional[list[Path]] = None,
) -> Generator[Path, None, None]:
    """Yield a freshly created GNUPGHOME directory and wipe it on exit.

    The directory lives under ``tempfile.gettempdir()`` (typically
    ``/tmp``) and is mode 0700. ``forbidden_prefixes`` defaults to the
    **configured** mirror data root (``mirror_paths.mirror_root()``,
    which honors ``PRAXIS_MIRROR_ROOT``) so a misconfigured TMPDIR
    pointing inside mirror storage fails fast with a clear error
    rather than silently colocating private key material with
    published bytes.

    A hard-coded ``/data/praxis/mirrors`` prefix would
    miss operators who relocate the mirror volume. Source the prefix
    from the same env var the rest of the engine uses so the guard
    tracks the real layout.

    Cleanup runs in a ``finally`` so an exception inside the block
    still wipes the directory. Cleanup errors are logged but never
    re-raised (we don't want to mask the original exception).
    """
    if forbidden_prefixes is None:
        # Imported lazily so the module stays importable when
        # ``mirror_paths`` (and its env-var lookups) aren't ready —
        # e.g. in cold-import unit tests.
        from . import mirror_paths

        forbidden_prefixes = [mirror_paths.mirror_root()]

    home = Path(tempfile.mkdtemp(prefix=_GNUPG_HOME_PREFIX))
    home_resolved = home.resolve()
    for forbidden in forbidden_prefixes:
        try:
            home_resolved.relative_to(forbidden.resolve())
        except (ValueError, FileNotFoundError):
            continue
        # Wipe before raising so we don't leak the empty home either.
        shutil.rmtree(home, ignore_errors=True)
        raise MirrorGPGError(
            f"GNUPGHOME landed under forbidden prefix {forbidden}; "
            "check TMPDIR — private key material must not co-locate "
            "with mirror storage."
        )

    home.chmod(0o700)
    try:
        yield home
    finally:
        try:
            shutil.rmtree(home, ignore_errors=False)
        except Exception as cleanup_err:  # pylint: disable=broad-except
            # Logging the path is fine — it's a tempdir name, not key
            # material. Logging the exception itself is fine for the
            # same reason.
            logger.warning(
                "Failed to wipe ephemeral GNUPGHOME at %s: %s",
                home,
                cleanup_err,
            )


def _run_gpg(
    home: Path,
    args: list[str],
    *,
    stdin: Optional[bytes] = None,
    timeout: int = _GPG_OP_TIMEOUT_S,
) -> subprocess.CompletedProcess:
    """Invoke gpg with ``home`` as GNUPGHOME and capture stdout/stderr.

    Stdout returns as bytes (armored output is ASCII; key listings are
    machine-parseable colon-format). Errors raise ``MirrorGPGError``
    with the return code and stderr — stderr is gpg's diagnostic
    channel and does not contain key material.
    """
    cmd = [
        GPG_BIN,
        "--homedir",
        str(home),
        "--batch",
        "--yes",
        "--quiet",
        *args,
    ]
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise MirrorGPGError(f"gpg binary not found at {GPG_BIN!r}") from exc
    except subprocess.TimeoutExpired as exc:
        raise MirrorGPGError(
            f"gpg timed out after {timeout}s running {args[0] if args else '?'}"
        ) from exc

    if result.returncode != 0:
        # stderr from gpg is diagnostic ("inappropriate ioctl",
        # "no such key", etc.), not secret. Safe to surface.
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise MirrorGPGError(
            f"gpg {args[0] if args else '?'} failed (rc={result.returncode}): "
            f"{stderr or '<no stderr>'}"
        )
    return result


def generate_keypair(home: Path, slug: str) -> str:
    """Generate a 4096-bit RSA signing keypair under ``home``.

    Returns the 40-char uppercase hex fingerprint. The uid is
    ``Praxis Mirror Signing <slug> <fingerprint>`` so a list-keys
    glance ties the row back to the mirror.

    No passphrase: the private key is protected by Vault's KV ACLs and
    by the ephemeral home (wiped after every use). A passphrase would
    only add a second secret to manage with no marginal protection.
    """
    if not slug or not re.match(r"^[a-z0-9_-]+$", slug):
        raise MirrorGPGError(f"refusing to generate key with invalid slug {slug!r}")

    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        f"Name-Real: Praxis Mirror Signing {slug}\n"
        "Name-Comment: managed by praxis\n"
        f"Name-Email: mirror-{slug}@praxis.local\n"
        "Expire-Date: 0\n"
        "%commit\n"
    ).encode("utf-8")

    _run_gpg(
        home,
        ["--gen-key"],
        stdin=batch,
        timeout=_GPG_GEN_TIMEOUT_S,
    )

    return _read_single_fingerprint(home)


def _read_single_fingerprint(home: Path) -> str:
    """Read the fingerprint of the (only) secret key in ``home``.

    Used after generation and after import. Asserts exactly one
    secret key is present — multiple would mean cross-contamination
    that should never happen in an ephemeral home.
    """
    result = _run_gpg(home, ["--with-colons", "--list-secret-keys"])
    fingerprints = _FPR_RE.findall(result.stdout.decode("utf-8", errors="replace"))
    if not fingerprints:
        raise MirrorGPGError("gpg --list-secret-keys returned no fingerprints")
    if len(set(fingerprints)) > 1:
        raise MirrorGPGError(
            f"ephemeral GNUPGHOME contains multiple keys "
            f"({len(set(fingerprints))}); refusing to proceed"
        )
    return fingerprints[0]


def export_public_armored(home: Path, fingerprint: str) -> str:
    """Return the armored public key for ``fingerprint`` as a string."""
    result = _run_gpg(home, ["--armor", "--export", fingerprint])
    return result.stdout.decode("utf-8")


def export_secret_armored(home: Path, fingerprint: str) -> str:
    """Return the armored secret key for ``fingerprint`` as a string.

    Caller must hand the return value directly to Vault and drop the
    reference; never log, never persist to disk outside Vault.
    """
    result = _run_gpg(home, ["--armor", "--export-secret-keys", fingerprint])
    return result.stdout.decode("utf-8")


def clearsign(home: Path, fingerprint: str, body: bytes) -> bytes:
    """Produce a clearsigned PGP message wrapping ``body`` (PRA-158 #2a).

    Used for apt's ``InRelease`` artifact, which embeds the ``Release``
    body inline between PGP cleartext armor headers and a PGP signature
    block. Apt prefers ``InRelease`` over the detached ``Release.gpg``
    when both are present; we emit both for the broadest client support.

    Caller imports the active signing key into ``home`` first (via
    ``import_and_verify``); this function selects the key by
    ``fingerprint`` and refuses if the home holds none. ``--digest-algo
    SHA256`` is pinned because some older toolchains default to SHA1
    which apt rejects.
    """
    expected = fingerprint.upper().strip()
    if not re.fullmatch(r"[A-F0-9]{40}", expected):
        raise MirrorGPGError(
            f"clearsign fingerprint must be 40 hex chars, got {fingerprint!r}"
        )
    result = _run_gpg(
        home,
        [
            "--armor",
            "--digest-algo",
            "SHA256",
            "--local-user",
            expected,
            "--clearsign",
            "--output",
            "-",
        ],
        stdin=body,
    )
    return result.stdout


def detached_sign(home: Path, fingerprint: str, body: bytes) -> bytes:
    """Produce a detached ASCII-armored PGP signature over ``body``
    (PRA-158 #2a).

    Used for apt's ``Release.gpg`` (over ``Release``), rpm's
    ``repomd.xml.asc`` (over ``repomd.xml``), and the Praxis manifest
    sidecar ``<run_id>.manifest.json.sig`` (over the canonical
    manifest JSON bytes).

    ``--digest-algo SHA256`` matches ``clearsign`` — every signature
    PRA-158 emits should use the same digest so a future audit of
    "what hash algorithm signed this mirror?" has one answer.
    """
    expected = fingerprint.upper().strip()
    if not re.fullmatch(r"[A-F0-9]{40}", expected):
        raise MirrorGPGError(
            f"detached_sign fingerprint must be 40 hex chars, got {fingerprint!r}"
        )
    result = _run_gpg(
        home,
        [
            "--armor",
            "--digest-algo",
            "SHA256",
            "--local-user",
            expected,
            "--detach-sign",
            "--output",
            "-",
        ],
        stdin=body,
    )
    return result.stdout


def import_armored_public(home: Path, armored_public: str) -> None:
    """Import an armored PUBLIC key (or set) into ``home`` (PRA-158 #4b).

    Used by the upstream-verify gate to build a transient keyring of
    trusted upstream archive keys. Unlike
    ``import_public_and_extract_fingerprint``, this does not enforce
    single-key bodies — operators add anchors one at a time via the
    CRUD endpoint, but the gate imports the whole DB set here.
    """
    if not armored_public or "BEGIN PGP PUBLIC KEY BLOCK" not in armored_public:
        raise MirrorGPGError("armored_public must contain a PGP PUBLIC KEY BLOCK")
    _run_gpg(home, ["--import"], stdin=armored_public.encode("utf-8"))


def verify_clearsigned(home: Path, signed_path: Path) -> None:
    """Verify a clearsigned file (e.g. apt's ``InRelease``) against
    the keyring loaded into ``home`` (PRA-158 #4b).

    Raises ``MirrorGPGError`` on any verification failure (no trusted
    signer, bad signature, malformed body). Caller turns that into a
    structured upstream-verify failure with the canonical alert event.
    """
    _run_gpg(home, ["--verify", str(signed_path)])


def verify_detached(home: Path, sig_path: Path, body_path: Path) -> None:
    """Verify a detached signature (e.g. apt's ``Release.gpg`` over
    ``Release``, or rpm's ``repomd.xml.asc`` over ``repomd.xml``)
    against the keyring loaded into ``home`` (PRA-158 #4b).

    Raises ``MirrorGPGError`` on any verification failure.
    """
    _run_gpg(home, ["--verify", str(sig_path), str(body_path)])


def import_public_and_extract_fingerprint(home: Path, armored_public: str) -> str:
    """Import an armored PUBLIC key and return its 40-char fingerprint
    (PRA-158 #4a, hardened in #4-b).

    Used by ``MirrorUpstreamKeyService.create_from_armored`` to derive
    the fingerprint operators don't need to provide manually. Asserts
    exactly one PRIMARY key in the input — operators paste single-key
    armored bodies, and one armor header is NOT the same as one key
    (a single PGP PUBLIC KEY BLOCK can pack multiple primary keys).
    After import, count ``pub:`` lines; multi-primary
    bodies are rejected so an operator can't silently land trust for
    keys not visible in the DB ``gpg_fingerprint`` row.

    NEVER touches Vault. NEVER persists material to disk outside the
    caller's ephemeral GNUPGHOME (the caller's ``with`` block wipes it).
    """
    if not armored_public or "BEGIN PGP PUBLIC KEY BLOCK" not in armored_public:
        raise MirrorGPGError("armored_public must be an armored PGP PUBLIC KEY BLOCK")
    if armored_public.count("BEGIN PGP PUBLIC KEY BLOCK") > 1:
        raise MirrorGPGError(
            "armored_public must contain exactly one PGP PUBLIC KEY BLOCK"
        )

    _run_gpg(home, ["--import"], stdin=armored_public.encode("utf-8"))
    output = _run_gpg(home, ["--with-colons", "--list-keys"]).stdout.decode(
        "utf-8", errors="replace"
    )

    # Count primary keys via ``pub:`` lines (one per primary). The
    # ``fpr:`` regex catches primary + subkey fingerprints — we want
    # the structural primary count here.
    primary_count = len(_PUB_RE.findall(output))
    if primary_count == 0:
        raise MirrorGPGError("gpg --list-keys returned no primary keys after import")
    if primary_count > 1:
        raise MirrorGPGError(
            f"armored body contains {primary_count} primary keys; this "
            "endpoint requires exactly one primary key per row so the "
            "stored gpg_fingerprint reflects everything trusted"
        )

    fingerprints = _FPR_RE.findall(output)
    if not fingerprints:
        raise MirrorGPGError("gpg --list-keys returned no fingerprints after import")
    # ``--list-keys --with-colons`` emits ``fpr`` for the primary
    # then ``fpr`` per subkey. The primary's fingerprint is the
    # first row.
    return fingerprints[0]


def import_and_verify(
    home: Path, armored_secret: str, expected_fingerprint: str
) -> None:
    """Import an armored secret key into ``home`` and verify the fingerprint.

    **Mismatch raises immediately** — refuse to use a key whose
    fingerprint diverges from what the DB row claims. This is the
    secret-boundary lock from project_pra158_design_locks.md: a Vault
    write that didn't make it back to DB consistently, or a swapped
    Vault entry, must not silently sign with the wrong key.

    Never logs the imported material; only logs structured fingerprints
    (those are public).
    """
    expected = expected_fingerprint.upper().strip()
    if not re.fullmatch(r"[A-F0-9]{40}", expected):
        raise MirrorGPGError(
            f"expected_fingerprint must be 40 hex chars, got {expected!r}"
        )

    _run_gpg(home, ["--import"], stdin=armored_secret.encode("utf-8"))
    actual = _read_single_fingerprint(home)
    if actual != expected:
        raise MirrorGPGError(
            "imported key fingerprint mismatch: "
            f"db says {expected}, vault material gave {actual}"
        )
