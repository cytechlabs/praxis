"""Distro-native package version ordering for Debian and RPM families.

Linux distribution packages do not use Python's PEP 440 version grammar.
Debian and RPM each define their own grammar and their own total order,
and the two disagree with PEP 440 on real shipped versions:

* ``1:2.39.3-9ubuntu6.5`` carries a Debian epoch. PEP 440 rejects it.
* ``5.6.1+really5.4.5-1ubuntu0.3`` is a Debian downgrade-in-place form.
  PEP 440 parses it as a local version and orders it below ``5.6.1-1``,
  while dpkg orders it above.
* ``1.1.1b`` is an upstream letter release. PEP 440 reads the ``b`` as a
  beta pre-release marker and orders it *below* ``1.1.1``; both dpkg and
  rpm order it above.

A wrong answer here is an audit-integrity problem, not a cosmetic one, so
this module implements the two distro orderings directly and refuses
anything it cannot parse. There is no fallback ordering: an unsupported
family or a malformed version is an error the caller must surface.

The implementations are ports of the reference algorithms:

* ``dpkg``'s ``verrevcmp`` and version grammar (deb-version(7)).
* ``rpm``'s ``rpmvercmp``, including ``~`` and ``^`` separators, plus
  ``rpmVersionCompare``'s epoch/version/release ordering.

Everything here is pure Python and side-effect free. No version string is
ever passed to a shell or to an external tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Version grammar families. These match the ``package_type`` values the
# package collector records on inventory rows and the ``package_family``
# vocabulary the mirror surfaces use.
SCHEME_DEB = "deb"
SCHEME_RPM = "rpm"

VALID_SCHEMES = frozenset({SCHEME_DEB, SCHEME_RPM})

# Package-manager and package-type names seen across host facts and
# inventory rows, mapped to the version grammar they produce. Anything
# absent is unsupported: the caller reports it rather than guessing.
_FAMILY_TO_SCHEME = {
    "apt": SCHEME_DEB,
    "apt-get": SCHEME_DEB,
    "dpkg": SCHEME_DEB,
    "deb": SCHEME_DEB,
    "debian": SCHEME_DEB,
    "dnf": SCHEME_RPM,
    "yum": SCHEME_RPM,
    "rpm": SCHEME_RPM,
}

_DIGITS = "0123456789"

# deb-version(7): upstream_version starts with a digit and may contain
# alphanumerics and ``. + - : ~``; a colon is only legal once an epoch has
# been consumed, and a hyphen only once a revision has been split off.
_DEB_EPOCH_RE = re.compile(r"^[0-9]+$")
_DEB_UPSTREAM_RE = re.compile(r"^[0-9][A-Za-z0-9.+~:-]*$")
_DEB_REVISION_RE = re.compile(r"^[A-Za-z0-9+.~]+$")

# RPM version and release segments. ``~`` and ``^`` are ordering
# separators; the rest are the characters real EVRs use.
_RPM_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+~^]+$")


class PackageVersionError(ValueError):
    """Base class for every refusal this module raises."""


class UnsupportedVersionScheme(PackageVersionError):
    """The package family does not map to a known version grammar."""


class InvalidPackageVersion(PackageVersionError):
    """The version string is not valid under the requested grammar."""


@dataclass(frozen=True)
class DebVersion:
    """A parsed Debian version: ``[epoch:]upstream[-revision]``."""

    epoch: int
    upstream: str
    revision: str


@dataclass(frozen=True)
class RpmVersion:
    """A parsed RPM EVR: ``[epoch:]version[-release]``.

    ``release`` is ``None`` when the string carried none, which orders
    below any present release exactly as ``rpmVersionCompare`` does.
    """

    epoch: int
    version: str
    release: Optional[str]


def scheme_for_package_family(family: Optional[str]) -> Optional[str]:
    """Map a package-manager or package-type name to a version grammar.

    Returns ``None`` for anything unrecognized, including ``unknown``, so
    the caller can raise a structured error instead of picking a default.
    """
    if not family:
        return None
    return _FAMILY_TO_SCHEME.get(family.strip().lower())


# ---------------------------------------------------------------------------
# Debian ordering
# ---------------------------------------------------------------------------


def parse_deb_version(value: str) -> DebVersion:
    """Parse a Debian version string, or raise ``InvalidPackageVersion``."""
    text = "" if value is None else str(value).strip()
    if not text:
        raise InvalidPackageVersion("empty Debian version")

    epoch = 0
    body = text
    if ":" in text:
        epoch_text, _, body = text.partition(":")
        if not _DEB_EPOCH_RE.match(epoch_text):
            raise InvalidPackageVersion(f"invalid Debian epoch in {text!r}")
        epoch = int(epoch_text)

    if "-" in body:
        upstream, _, revision = body.rpartition("-")
    else:
        upstream, revision = body, ""

    if not _DEB_UPSTREAM_RE.match(upstream):
        raise InvalidPackageVersion(f"invalid Debian upstream version in {text!r}")
    if revision and not _DEB_REVISION_RE.match(revision):
        raise InvalidPackageVersion(f"invalid Debian revision in {text!r}")
    if "-" in body and not revision:
        raise InvalidPackageVersion(f"empty Debian revision in {text!r}")

    return DebVersion(epoch=epoch, upstream=upstream, revision=revision)


def _deb_order(char: str) -> int:
    """dpkg's ``order()``: ``~`` sorts before everything, including the
    end of the string; digits and the end of the string tie at zero;
    letters sort by their code point; every other character sorts after
    all letters.
    """
    if char == "":
        return 0
    if char in _DIGITS:
        return 0
    if ("a" <= char <= "z") or ("A" <= char <= "Z"):
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _deb_verrevcmp(left: str, right: str) -> int:
    """dpkg's ``verrevcmp``: alternate between non-digit runs compared
    character by character under ``_deb_order``, and digit runs compared
    as numbers with leading zeros ignored.
    """
    i = 0
    j = 0
    len_l = len(left)
    len_r = len(right)

    while i < len_l or j < len_r:
        first_diff = 0

        while (i < len_l and left[i] not in _DIGITS) or (
            j < len_r and right[j] not in _DIGITS
        ):
            order_l = _deb_order(left[i] if i < len_l else "")
            order_r = _deb_order(right[j] if j < len_r else "")
            if order_l != order_r:
                return -1 if order_l < order_r else 1
            i += 1
            j += 1

        while i < len_l and left[i] == "0":
            i += 1
        while j < len_r and right[j] == "0":
            j += 1

        while i < len_l and j < len_r and left[i] in _DIGITS and right[j] in _DIGITS:
            if first_diff == 0:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1

        # A longer remaining digit run is the larger number.
        if i < len_l and left[i] in _DIGITS:
            return 1
        if j < len_r and right[j] in _DIGITS:
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1

    return 0


def compare_deb_versions(left: str, right: str) -> int:
    """Order two Debian versions: -1, 0, or 1."""
    parsed_l = parse_deb_version(left)
    parsed_r = parse_deb_version(right)

    if parsed_l.epoch != parsed_r.epoch:
        return -1 if parsed_l.epoch < parsed_r.epoch else 1
    result = _deb_verrevcmp(parsed_l.upstream, parsed_r.upstream)
    if result:
        return result
    return _deb_verrevcmp(parsed_l.revision, parsed_r.revision)


# ---------------------------------------------------------------------------
# RPM ordering
# ---------------------------------------------------------------------------


def parse_rpm_version(value: str) -> RpmVersion:
    """Parse an RPM EVR string, or raise ``InvalidPackageVersion``."""
    text = "" if value is None else str(value).strip()
    if not text:
        raise InvalidPackageVersion("empty RPM version")

    epoch = 0
    body = text
    if ":" in text:
        epoch_text, _, body = text.partition(":")
        if not _DEB_EPOCH_RE.match(epoch_text):
            raise InvalidPackageVersion(f"invalid RPM epoch in {text!r}")
        epoch = int(epoch_text)

    if "-" in body:
        version, _, release = body.rpartition("-")
        if not release:
            raise InvalidPackageVersion(f"empty RPM release in {text!r}")
    else:
        version, release = body, None

    if not _RPM_SEGMENT_RE.match(version):
        raise InvalidPackageVersion(f"invalid RPM version in {text!r}")
    if release is not None and not _RPM_SEGMENT_RE.match(release):
        raise InvalidPackageVersion(f"invalid RPM release in {text!r}")

    return RpmVersion(epoch=epoch, version=version, release=release)


def _is_rpm_alnum(char: str) -> bool:
    return ("a" <= char <= "z") or ("A" <= char <= "Z") or (char in _DIGITS)


def _is_rpm_alpha(char: str) -> bool:
    return ("a" <= char <= "z") or ("A" <= char <= "Z")


def _rpmvercmp(left: str, right: str) -> int:
    """rpm's ``rpmvercmp``: skip separators, honour ``~`` (sorts before
    everything) and ``^`` (sorts after the bare base version), then
    compare alternating alphabetic and numeric runs. A numeric run
    outranks an alphabetic one.
    """
    if left == right:
        return 0

    i = 0
    j = 0
    len_l = len(left)
    len_r = len(right)

    while i < len_l or j < len_r:
        while i < len_l and not _is_rpm_alnum(left[i]) and left[i] not in "~^":
            i += 1
        while j < len_r and not _is_rpm_alnum(right[j]) and right[j] not in "~^":
            j += 1

        left_tilde = i < len_l and left[i] == "~"
        right_tilde = j < len_r and right[j] == "~"
        if left_tilde or right_tilde:
            if not left_tilde:
                return 1
            if not right_tilde:
                return -1
            i += 1
            j += 1
            continue

        left_caret = i < len_l and left[i] == "^"
        right_caret = j < len_r and right[j] == "^"
        if left_caret or right_caret:
            if i >= len_l:
                return -1
            if j >= len_r:
                return 1
            if not left_caret:
                return 1
            if not right_caret:
                return -1
            i += 1
            j += 1
            continue

        if i >= len_l or j >= len_r:
            break

        start_l = i
        start_r = j
        numeric = left[i] in _DIGITS
        if numeric:
            while i < len_l and left[i] in _DIGITS:
                i += 1
            while j < len_r and right[j] in _DIGITS:
                j += 1
        else:
            while i < len_l and _is_rpm_alpha(left[i]):
                i += 1
            while j < len_r and _is_rpm_alpha(right[j]):
                j += 1

        segment_l = left[start_l:i]
        segment_r = right[start_r:j]
        # Segments of different types: the numeric one is the newer.
        if not segment_r:
            return 1 if numeric else -1

        if numeric:
            segment_l = segment_l.lstrip("0")
            segment_r = segment_r.lstrip("0")
            if len(segment_l) != len(segment_r):
                return 1 if len(segment_l) > len(segment_r) else -1

        if segment_l != segment_r:
            return -1 if segment_l < segment_r else 1

    if i >= len_l and j >= len_r:
        return 0
    return -1 if i >= len_l else 1


def compare_rpm_versions(left: str, right: str) -> int:
    """Order two RPM EVR strings: -1, 0, or 1."""
    parsed_l = parse_rpm_version(left)
    parsed_r = parse_rpm_version(right)

    if parsed_l.epoch != parsed_r.epoch:
        return -1 if parsed_l.epoch < parsed_r.epoch else 1
    result = _rpmvercmp(parsed_l.version, parsed_r.version)
    if result:
        return result
    # A missing release orders below any present release.
    if parsed_l.release is None and parsed_r.release is None:
        return 0
    if parsed_l.release is None:
        return -1
    if parsed_r.release is None:
        return 1
    return _rpmvercmp(parsed_l.release, parsed_r.release)


# ---------------------------------------------------------------------------
# Scheme-dispatching entry points
# ---------------------------------------------------------------------------


def validate_version(scheme: str, value: str) -> None:
    """Raise ``UnsupportedVersionScheme`` or ``InvalidPackageVersion`` if
    ``value`` cannot be ordered under ``scheme``.
    """
    if scheme == SCHEME_DEB:
        parse_deb_version(value)
        return
    if scheme == SCHEME_RPM:
        parse_rpm_version(value)
        return
    raise UnsupportedVersionScheme(f"unsupported version scheme: {scheme!r}")


def is_valid_version(scheme: str, value: str) -> bool:
    """Whether ``value`` parses under ``scheme``.

    An unsupported scheme still raises: only the version string is being
    tested here, and silently reporting "invalid" for a family we never
    supported would hide the real problem.
    """
    try:
        validate_version(scheme, value)
    except InvalidPackageVersion:
        return False
    return True


def compare_versions(scheme: str, left: str, right: str) -> int:
    """Order two versions under ``scheme``: -1, 0, or 1."""
    if scheme == SCHEME_DEB:
        return compare_deb_versions(left, right)
    if scheme == SCHEME_RPM:
        return compare_rpm_versions(left, right)
    raise UnsupportedVersionScheme(f"unsupported version scheme: {scheme!r}")


def version_at_least(scheme: str, observed: str, minimum: str) -> bool:
    """Whether ``observed`` meets or exceeds ``minimum`` under ``scheme``."""
    return compare_versions(scheme, observed, minimum) >= 0
