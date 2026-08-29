"""Armor envelopes for tests, built at runtime.

A private-key armor header reads as key material to a secret scanner no
matter what sits between the markers, so a committed literal turns every
scan of the tree into a triage exercise. These builders assemble the
markers from fragments at call time and return the exact strings the code
under test expects, keeping the placeholder body readable at each call
site while no contiguous header remains in source.
"""

from __future__ import annotations

_DASHES = "-" * 5
_PRIVATE_KEY = "PRIVATE KEY"


def pgp_private_block(body: str) -> str:
    """A PGP private-key armor block wrapping ``body``.

    The closing marker is the short ``-----END-----`` form the fake gpg
    shims emit. Nothing reads it back.
    """
    opening = f"{_DASHES}BEGIN PGP {_PRIVATE_KEY} BLOCK{_DASHES}"
    return f"{opening}\n{body}\n{_DASHES}END{_DASHES}\n"


def openssh_private_block(body: str) -> str:
    """An OpenSSH private-key PEM block wrapping ``body``, unterminated.

    Returned without a trailing newline so callers control what follows.
    """
    marker = f"OPENSSH {_PRIVATE_KEY}"
    return f"{_DASHES}BEGIN {marker}{_DASHES}\n{body}\n{_DASHES}END {marker}{_DASHES}"
