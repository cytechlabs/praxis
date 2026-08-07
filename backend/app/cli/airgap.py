"""Airgap operator CLI (PRA-160 slice #5).

Two subcommands designed for off-the-cuff inspection during
disconnected workflows — neither touches the database or the backend
service. Both run inside the backend container against a tar mounted
on disk:

  praxis-airgap inspect <bundle.tar>
      Read ``bundle.json`` from the tar root and pretty-print the
      descriptor body. Useful for "what's in this thing" before
      deciding to import. No signature verification — operator can
      see the descriptor even with no trust pin yet.

  praxis-airgap verify <bundle.tar> --key-file <pubkey.asc>
      Read ``bundle.json`` + ``bundle.json.sig`` from the tar root
      and run ``mirror_gpg.verify_detached`` against the
      operator-supplied public key. Prints PASS / FAIL with the
      bundle_id + kind + parent_bundle_id (if any). Useful for a
      pre-import sanity check that the operator's pinned key
      actually signs this bundle.

Locks (PRA-160 design conversation):
  * Standalone — no DB, no Vault. The CLI runs inside the backend
    container so it has access to the bundled gpg binary; for fully
    out-of-band verification an operator can also use system
    ``gpg --verify`` on the extracted ``bundle.json.sig``.
  * No tar extraction beyond the descriptor pair. ``inspect`` /
    ``verify`` never touch payload bytes, never write to the
    filesystem, never mutate state. They're read-only inspection.
  * ``inspect`` does NOT run the importer's signature/integrity
    chain. It's intentionally low-trust: an operator may want to
    look at a bundle before deciding whether to pin its key.
  * Exit codes: 0 = success, 2 = verify failed, 3 = bad arguments
    (including argparse failures: unknown subcommand, missing
    --key-file, etc.), 4 = tar / IO error, 5 = bundle requires a
    newer Praxis (unsupported ``bundle_version``).

Invocation:

    docker compose exec backend python -m app.cli.airgap inspect /tmp/bundle.tar
    docker compose exec backend python -m app.cli.airgap verify /tmp/bundle.tar \
        --key-file /tmp/exporter-pub.asc
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tarfile
from pathlib import Path
from typing import Optional, Tuple

from ..services import mirror_gpg
from ..services.airgap.schema import UnsupportedSchemaVersion, deserialize_descriptor

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_VERIFY_FAILED = 2
EXIT_BAD_ARGS = 3
EXIT_IO_ERROR = 4
# Distinguish a future-version bundle from generic
# IO/parse errors. Operator scripts can branch on this so a
# legitimate "this Praxis is too old, upgrade" surface doesn't get
# conflated with "the tar is corrupt."
EXIT_UNSUPPORTED_VERSION = 5


class _CLIArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that exits with ``EXIT_BAD_ARGS`` on any
    parse failure.

    argparse's default ``error`` calls ``sys.exit(2)`` which
    collides with our documented ``EXIT_VERIFY_FAILED=2``. Override
    the exit-code so missing subcommand / unknown option / omitted
    ``--key-file`` honor the documented contract.
    """

    def error(self, message):  # type: ignore[override]
        # Mirror argparse's default formatting on stderr, then
        # exit with our documented bad-args code.
        self.print_usage(sys.stderr)
        self.exit(EXIT_BAD_ARGS, f"{self.prog}: error: {message}\n")


_BUNDLE_DESCRIPTOR_NAME = "bundle.json"
_BUNDLE_DESCRIPTOR_SIG_NAME = "bundle.json.sig"


def _read_descriptor_pair(tar_path: Path) -> Tuple[bytes, bytes]:
    """Read ``bundle.json`` and ``bundle.json.sig`` from the tar root.

    Stand-alone duplicate of ``importer._read_descriptor_pair`` so
    the CLI doesn't drag the importer's DB/staging dependencies
    into a read-only inspection. The bytes-on-disk semantics are
    identical: tar root members named exactly ``bundle.json`` and
    ``bundle.json.sig``, both regular files.
    """
    body: Optional[bytes] = None
    sig: Optional[bytes] = None
    with tarfile.open(tar_path, mode="r") as tar:
        for member in tar:
            if member.name == _BUNDLE_DESCRIPTOR_NAME and member.isfile():
                fh = tar.extractfile(member)
                if fh is not None:
                    body = fh.read()
            elif member.name == _BUNDLE_DESCRIPTOR_SIG_NAME and member.isfile():
                fh = tar.extractfile(member)
                if fh is not None:
                    sig = fh.read()
            if body is not None and sig is not None:
                break
    if body is None or sig is None:
        raise FileNotFoundError(
            f"tar at {tar_path} is missing bundle.json"
            + ("" if body is not None else " (body)")
            + ("" if sig is not None else " (signature)")
        )
    return body, sig


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def cmd_inspect(args: argparse.Namespace) -> int:
    """Pretty-print the bundle descriptor from a tar without verifying."""
    tar_path = Path(args.bundle)
    if not tar_path.exists():
        print(f"error: bundle tar not found: {tar_path}", file=sys.stderr)
        return EXIT_IO_ERROR
    try:
        body, _sig = _read_descriptor_pair(tar_path)
    except (tarfile.TarError, OSError, FileNotFoundError) as exc:
        print(
            f"error: cannot read descriptor from {tar_path}: {exc}",
            file=sys.stderr,
        )
        return EXIT_IO_ERROR
    try:
        # Use deserialize_descriptor to surface bundle_version
        # mismatches up front — operators inspecting an unsupported
        # bundle should see the version refusal rather than a
        # confusing field-shape error.
        descriptor = deserialize_descriptor(body)
    except UnsupportedSchemaVersion as exc:
        # Typed exception lets us cleanly
        # surface "this Praxis is too old" with a dedicated exit
        # code instead of a generic IO error. Caught BEFORE the
        # broader malformed-descriptor branch since it's a
        # ValueError subclass.
        print(
            f"error: bundle requires a newer Praxis: {exc}",
            file=sys.stderr,
        )
        return EXIT_UNSUPPORTED_VERSION
    except (ValueError, KeyError, TypeError) as exc:
        # Malformed-but-versioned descriptors raise
        # KeyError (missing required field) or TypeError (wrong
        # field shape) from ``deserialize_descriptor``'s
        # ``ProfileDescriptor(**p)`` constructors. ``ValueError``
        # also covers a malformed JSON body from ``json.loads``.
        # Operators get a clean EXIT_IO_ERROR instead of a Python
        # traceback.
        print(f"error: descriptor unreadable: {exc!r}", file=sys.stderr)
        return EXIT_IO_ERROR
    parsed = json.loads(body)
    print(json.dumps(parsed, sort_keys=True, indent=2))
    print(
        f"\n# bundle_id={descriptor.bundle_id} kind={descriptor.kind} "
        f"parent_bundle_id={descriptor.parent_bundle_id} "
        f"profiles={len(descriptor.profiles)} "
        f"channels={len(descriptor.channels)} "
        f"mirrors={len(descriptor.mirrors)} "
        f"payload_index_entries={len(descriptor.payload_index)}",
        file=sys.stderr,
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify bundle.json.sig against an operator-supplied public key."""
    tar_path = Path(args.bundle)
    key_path = Path(args.key_file)
    if not tar_path.exists():
        print(f"error: bundle tar not found: {tar_path}", file=sys.stderr)
        return EXIT_IO_ERROR
    if not key_path.exists():
        print(f"error: key file not found: {key_path}", file=sys.stderr)
        return EXIT_BAD_ARGS

    try:
        body, sig = _read_descriptor_pair(tar_path)
    except (tarfile.TarError, OSError, FileNotFoundError) as exc:
        print(
            f"error: cannot read descriptor from {tar_path}: {exc}",
            file=sys.stderr,
        )
        return EXIT_IO_ERROR

    try:
        armored = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read key file {key_path}: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    try:
        with mirror_gpg.ephemeral_gnupg_home() as home:
            mirror_gpg.import_armored_public(home, armored)
            body_path = home / "body"
            sig_path = home / "body.sig"
            body_path.write_bytes(body)
            sig_path.write_bytes(sig)
            mirror_gpg.verify_detached(home, sig_path, body_path)
    except mirror_gpg.MirrorGPGError as exc:
        print(f"FAIL: bundle.json.sig does not verify: {exc}", file=sys.stderr)
        return EXIT_VERIFY_FAILED

    # Verify successful — also surface descriptor identity for the
    # operator's confirmation.
    try:
        descriptor = deserialize_descriptor(body)
    except UnsupportedSchemaVersion as exc:
        # Signature verified but Praxis is too old to read the body.
        # Operator pinned the right key but should upgrade.
        print(
            "PASS: signature verifies, but bundle requires a newer Praxis "
            f"to read: {exc}",
            file=sys.stderr,
        )
        return EXIT_UNSUPPORTED_VERSION
    except (ValueError, KeyError, TypeError) as exc:
        # Same broadened catch as cmd_inspect. The
        # signature was valid but the body itself is unparseable;
        # surface as a soft warning + EXIT_OK so operators don't
        # lose the "signature verified" signal, but tag stderr.
        print(
            "WARN: signature verified but descriptor body can't be parsed: " f"{exc!r}",
            file=sys.stderr,
        )
        return EXIT_OK
    print(
        f"PASS: bundle.json.sig verifies against {key_path}\n"
        f"  bundle_id={descriptor.bundle_id}\n"
        f"  kind={descriptor.kind}\n"
        f"  parent_bundle_id={descriptor.parent_bundle_id}\n"
        f"  praxis_instance_signing_fingerprint="
        f"{descriptor.praxis_instance_signing_fingerprint}"
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = _CLIArgumentParser(
        prog="praxis-airgap",
        description=(
            "Airgap bundle operator inspection. Read-only: neither "
            "subcommand modifies any DB or filesystem state."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser(
        "inspect",
        help="Pretty-print the descriptor JSON from a bundle tar.",
    )
    inspect.add_argument(
        "bundle",
        type=str,
        help="Path to the bundle .tar file.",
    )
    inspect.set_defaults(func=cmd_inspect)

    verify = subparsers.add_parser(
        "verify",
        help=(
            "Verify bundle.json.sig against an operator-supplied "
            "public key. Standalone — does not consult Praxis "
            "trust pins."
        ),
    )
    verify.add_argument(
        "bundle",
        type=str,
        help="Path to the bundle .tar file.",
    )
    verify.add_argument(
        "--key-file",
        required=True,
        type=str,
        help="Path to the armored PGP public key to verify against.",
    )
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover — module-as-script entry
    sys.exit(main())
