#!/usr/bin/env python3
"""Check a generated agent SBOM against the release it claims to describe.

The SBOM travels with the tarball and is what downstream supply-chain
tooling reads, so a primary component that reports the wrong version is a
silent correctness bug rather than a cosmetic one. The generator derives
that version from a flag; this asserts the result rather than trusting it.

Checks, for one SBOM:

- it is CycloneDX JSON at the expected spec version;
- the primary component is the agent, typed as an application, and carries
  the release version;
- every version-bearing identifier of the primary component (``purl`` and
  ``bom-ref``) reports the same version;
- the purl targets the architecture the file is named for; and
- serial number and timestamp are absent, since either would make the
  output differ between otherwise identical builds.

Exits non-zero with a specific message on the first failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

MODULE_PATH = "github.com/cytechlabs/praxis/agent"


def _fail(message: str) -> None:
    print(f"verify-sbom: {message}", file=sys.stderr)
    raise SystemExit(1)


def _purl_version(purl: str) -> str:
    """Return the version segment of a purl.

    A purl looks like ``pkg:golang/<name>@<version>?<qualifiers>#<subpath>``.
    The version ends at the first qualifier or subpath separator."""
    if "@" not in purl:
        _fail(f"purl carries no version: {purl}")
    tail = purl.rsplit("@", 1)[1]
    return re.split(r"[?#]", tail, maxsplit=1)[0]


def _purl_qualifiers(purl: str) -> Dict[str, str]:
    if "?" not in purl:
        return {}
    qualifiers = re.split(r"[?#]", purl)[1]
    pairs: Dict[str, str] = {}
    for part in qualifiers.split("&"):
        if "=" in part:
            key, value = part.split("=", 1)
            pairs[key] = value
    return pairs


def _check(document: Dict[str, Any], args: argparse.Namespace) -> List[str]:
    checks: List[str] = []

    if document.get("bomFormat") != "CycloneDX":
        _fail(f"bomFormat is {document.get('bomFormat')!r}, expected 'CycloneDX'")
    if document.get("specVersion") != args.spec_version:
        _fail(
            f"specVersion is {document.get('specVersion')!r}, "
            f"expected {args.spec_version!r}"
        )
    checks.append(f"CycloneDX {args.spec_version}")

    # Reproducibility: both fields are omitted by the generator flags, and a
    # reappearance would make two identical builds produce different bytes.
    if "serialNumber" in document:
        _fail("serialNumber is present; SBOM would differ between builds")
    if "timestamp" in document.get("metadata", {}):
        _fail("metadata.timestamp is present; SBOM would differ between builds")
    checks.append("no serial number or timestamp")

    component = document.get("metadata", {}).get("component")
    if not isinstance(component, dict):
        _fail("metadata.component is missing")

    if component.get("type") != "application":
        _fail(f"primary component type is {component.get('type')!r}, expected 'application'")
    if component.get("name") != MODULE_PATH:
        _fail(f"primary component name is {component.get('name')!r}, expected {MODULE_PATH!r}")
    if component.get("version") != args.version:
        _fail(
            f"primary component version is {component.get('version')!r}, "
            f"expected {args.version!r}"
        )
    checks.append(f"primary component {MODULE_PATH} {args.version}")

    # A purl or bom-ref still carrying a pseudo-version would make the SBOM
    # disagree with itself, which is exactly the failure this guards.
    for field in ("purl", "bom-ref"):
        value = component.get(field)
        if not value:
            _fail(f"primary component has no {field}")
        found = _purl_version(value)
        if found != args.version:
            _fail(f"primary component {field} reports version {found!r}, expected {args.version!r}")
    checks.append("purl and bom-ref versions match")

    qualifiers = _purl_qualifiers(component["purl"])
    if qualifiers.get("goarch") != args.goarch:
        _fail(
            f"primary component purl goarch is {qualifiers.get('goarch')!r}, "
            f"expected {args.goarch!r}"
        )
    if qualifiers.get("goos") != "linux":
        _fail(f"primary component purl goos is {qualifiers.get('goos')!r}, expected 'linux'")
    checks.append(f"targets linux/{args.goarch}")

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--version", required=True, help="expected release version, e.g. v1.0.0")
    parser.add_argument("--spec-version", required=True, help="expected CycloneDX spec version")
    parser.add_argument("--goarch", required=True, help="expected target architecture")
    args = parser.parse_args()

    if not args.sbom.is_file():
        _fail(f"{args.sbom} does not exist")

    try:
        document = json.loads(args.sbom.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"{args.sbom} is not valid JSON: {exc}")

    checks = _check(document, args)
    print(f"verify-sbom: {args.sbom.name} OK ({'; '.join(checks)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
