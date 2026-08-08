#!/usr/bin/env python3
"""Build the public release index for a whole-product Praxis release.

The index is the release record. It names every shipped component, binds each
one to the source commit and version it was built from, and points at the SBOM,
provenance, and checksum material a consumer needs to verify it. It is
generated from the release run's own outputs rather than written by hand, so it
cannot describe an artifact that was never produced.

Nothing here publishes. The script reads what the release workflow built,
refuses to describe an incomplete or mismatched set, and writes two files:

- a machine-readable JSON record, and
- a public markdown summary suitable for a release body.

Every input is checked before either file is written:

- version, tag, and commit agree and are well formed;
- each published image resolves to an immutable ``sha256:`` digest;
- each image SBOM is CycloneDX at the expected spec version, and its primary
  component names the exact image reference that was scanned, so an SBOM
  produced from some other build cannot be attached to this one; and
- the agent checksum manifest lists every artifact expected for this version.

A publish run additionally requires a digest, tag list, and attestations for
every image, and the complete manifest of the matching agent release: the
record it produces is the whole-product release record, so a knowingly
incomplete one is not publishable. A validation run may describe an agent
release that has not been cut yet, and records that nothing was published
rather than inventing digests for images that were never pushed.

Exits non-zero with a specific message on the first failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

SCHEMA = "praxis.release-index/1"
PRODUCT = "Praxis"

VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}(?:-[0-9A-Za-z.-]+)?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PACKAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")

GATE_STATUSES = ("passed", "skipped")

# The agent is released under its own tag by its own workflow. This is the
# artifact set that release publishes; the index consumes it rather than
# rebuilding or redefining it.
AGENT_ARCHITECTURES = ("amd64", "arm64")
AGENT_MANIFEST = "checksums.txt"
AGENT_SIGNATURE = "checksums.txt.sig"
AGENT_CERTIFICATE = "checksums.txt.pem"


def _fail(message: str) -> None:
    print(f"release-index: {message}", file=sys.stderr)
    raise SystemExit(1)


def _split_pair(value: str, flag: str) -> Tuple[str, str]:
    """Split a ``name=value`` command-line pair."""
    if "=" not in value:
        _fail(f"{flag} expects name=value, got {value!r}")
    name, _, rest = value.partition("=")
    name = name.strip()
    rest = rest.strip()
    if not name or not rest:
        _fail(f"{flag} expects a non-empty name and value, got {value!r}")
    return name, rest


def _collect_pairs(values: List[str], flag: str) -> Dict[str, str]:
    collected: Dict[str, str] = {}
    for value in values or []:
        name, rest = _split_pair(value, flag)
        if name in collected:
            _fail(f"{flag} given twice for {name!r}")
        collected[name] = rest
    return collected


def _purl_version(purl: str) -> str:
    """Return the version segment of a purl.

    A purl is ``pkg:<type>/<name>@<version>?<qualifiers>#<subpath>``; the
    version ends at the first qualifier or subpath separator."""
    if "@" not in purl:
        return ""
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
            pairs[key] = unquote(value)
    return pairs


def _load_json(path: Path, label: str) -> dict:
    if not path.is_file():
        _fail(f"{label} {path.name} does not exist")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"{label} {path.name} is not valid JSON: {exc}")
    return {}  # unreachable; _fail raises


def _verify_image_sbom(path: Path, reference: str, spec_version: str) -> None:
    """Check that one SBOM describes the exact image it is published beside.

    The binding that matters is the primary component: a CycloneDX document
    generated from a different build is otherwise indistinguishable from the
    right one once it is renamed."""
    document = _load_json(path, "SBOM")

    if document.get("bomFormat") != "CycloneDX":
        _fail(f"{path.name} bomFormat is {document.get('bomFormat')!r}, expected 'CycloneDX'")
    if document.get("specVersion") != spec_version:
        _fail(
            f"{path.name} specVersion is {document.get('specVersion')!r}, "
            f"expected {spec_version!r}"
        )

    component = document.get("metadata", {}).get("component")
    if not isinstance(component, dict):
        _fail(f"{path.name} has no metadata.component")

    if component.get("type") != "container":
        _fail(
            f"{path.name} primary component type is {component.get('type')!r}, "
            "expected 'container'"
        )
    if component.get("name") != reference:
        _fail(
            f"{path.name} describes {component.get('name')!r}, "
            f"expected the published image {reference!r}"
        )

    # When the image was scanned by digest, the purl carries that digest too.
    # Catching a disagreement here means the document cannot claim one image in
    # its name and another in its identifiers.
    if "@sha256:" in reference:
        digest = reference.split("@", 1)[1]
        purl = component.get("purl") or ""
        if _purl_version(purl) != digest:
            _fail(
                f"{path.name} purl reports {_purl_version(purl)!r}, "
                f"expected the published digest {digest!r}"
            )
        repository = reference.split("@", 1)[0]
        qualifiers = _purl_qualifiers(purl)
        if qualifiers.get("repository_url") != repository:
            _fail(
                f"{path.name} purl repository_url is "
                f"{qualifiers.get('repository_url')!r}, expected {repository!r}"
            )


def _parse_agent_manifest(path: Path, version: str) -> List[dict]:
    """Read the agent release checksum manifest into index entries.

    The manifest is the agent release's own published output. Consuming it
    keeps one source of truth for those checksums instead of recomputing them
    from a rebuild that might not be the released one."""
    if not path.is_file():
        _fail(f"agent checksum manifest {path.name} does not exist")

    entries: List[dict] = []
    seen: Dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            _fail(f"agent checksum manifest line {number} is malformed")
        checksum, name = parts[0], parts[1].lstrip("*").strip()
        if not SHA256_RE.fullmatch(checksum):
            _fail(f"agent checksum manifest line {number} has a malformed sha256")
        if "/" in name or name != Path(name).name:
            _fail(f"agent checksum manifest line {number} names a path, not an artifact")
        if name in seen:
            _fail(f"agent checksum manifest lists {name} twice")
        seen[name] = checksum
        entries.append({"name": name, "sha256": checksum})

    expected = []
    for arch in AGENT_ARCHITECTURES:
        expected.append(f"praxis-agent-{version}-linux-{arch}.tar.gz")
        expected.append(f"praxis-agent-{version}-linux-{arch}-sbom.cdx.json")
    missing = [name for name in expected if name not in seen]
    if missing:
        _fail(
            "agent checksum manifest is incomplete for "
            f"{version}; missing {', '.join(missing)}"
        )

    return entries


def _published_image_identity(
    name: str,
    reference: str,
    repository: str,
    digest: Optional[str],
    tag_list: str,
    version: str,
) -> List[str]:
    """Check how a published image is named, and return the tags it carries.

    A published image is identified by its digest; the tags are convenience
    labels that must at least include the version being released, or the
    release would have no immutable name in the registry."""
    if not digest:
        _fail(f"no --image-digest for {name}; a published image is identified by digest")
    if not DIGEST_RE.fullmatch(digest):
        _fail(f"--image-digest for {name} is not a sha256 digest: {digest!r}")

    expected_reference = f"{repository}@{digest}"
    if reference != expected_reference:
        _fail(
            f"--image-ref for {name} is {reference!r}, expected the published "
            f"digest reference {expected_reference!r}"
        )

    tags = [tag.strip() for tag in tag_list.split(",") if tag.strip()]
    if not tags:
        _fail(f"no --image-tags for {name}; a published image carries at least its version")
    if version not in tags:
        _fail(f"--image-tags for {name} does not include the release version {version!r}")
    return tags


def _image_components(args: argparse.Namespace, publishing: bool) -> List[dict]:
    references = _collect_pairs(args.image_ref, "--image-ref")
    if not references:
        _fail("no --image-ref given; a release describes at least one image")

    digests = _collect_pairs(args.image_digest, "--image-digest")
    tag_lists = _collect_pairs(args.image_tags, "--image-tags")
    sboms = _collect_pairs(args.image_sbom, "--image-sbom")

    for flag, given in (("--image-digest", digests), ("--image-tags", tag_lists), ("--image-sbom", sboms)):
        unknown = sorted(set(given) - set(references))
        if unknown:
            _fail(f"{flag} names {unknown[0]!r}, which has no --image-ref")

    components: List[dict] = []
    for name in sorted(references):
        if not PACKAGE_RE.fullmatch(name):
            _fail(f"{name!r} is not a valid package name")

        reference = references[name]
        repository = f"{args.registry}/{args.owner}/{name}"
        sbom_path = sboms.get(name)
        if not sbom_path:
            _fail(f"no --image-sbom for {name}; every published image ships an SBOM")

        digest = digests.get(name)
        if publishing:
            tags = _published_image_identity(
                name, reference, repository, digest, tag_lists.get(name, ""), args.version
            )
        elif digest:
            _fail(
                f"--image-digest given for {name} in a validation run; nothing was "
                "published, so there is no immutable digest to record"
            )
        else:
            tags = []

        _verify_image_sbom(Path(sbom_path), reference, args.sbom_spec_version)

        component = {
            "name": name,
            "kind": "container-image",
            "registry": args.registry,
            "repository": repository,
            "digest": digest,
            "tags": tags,
            "pull_by_digest": f"{repository}@{digest}" if digest else None,
            "sbom": {
                "file": Path(sbom_path).name,
                "format": "CycloneDX",
                "spec_version": args.sbom_spec_version,
                "location": "release-asset" if publishing else "workflow-artifact",
            },
            "attestations": sorted(args.attestations) if publishing else [],
        }
        components.append(component)
    return components


def _agent_component(args: argparse.Namespace, publishing: bool) -> Optional[dict]:
    """Describe the agent release this application release ships alongside.

    A published index is the whole-product release record, so publishing
    requires the matching agent release to exist already and its manifest to be
    complete. A validation run may describe an agent release that has not been
    cut yet, because nothing is being recorded permanently."""
    if not args.agent_tag:
        if publishing:
            _fail(
                "--agent-tag is required when publishing; the release record must "
                "name the agent release it ships with"
            )
        return None

    agent_version = args.agent_version or f"v{args.version}"
    if not VERSION_RE.fullmatch(agent_version.lstrip("v")):
        _fail(f"--agent-version {agent_version!r} is not a version")
    if args.agent_tag != f"agent-{agent_version}":
        _fail(
            f"--agent-tag {args.agent_tag!r} does not match agent release "
            f"{agent_version!r}"
        )

    component = {
        "name": "praxis-agent",
        "kind": "release-archive",
        "release_tag": args.agent_tag,
        "release_url": (
            f"https://github.com/{args.repository}/releases/tag/{args.agent_tag}"
        ),
        "version": agent_version,
    }

    if args.agent_checksums:
        component["status"] = "published"
        component["artifacts"] = _parse_agent_manifest(Path(args.agent_checksums), agent_version)
        component["signature"] = {
            "scheme": "sigstore-keyless",
            "manifest": AGENT_MANIFEST,
            "signature": AGENT_SIGNATURE,
            "certificate": AGENT_CERTIFICATE,
        }
    elif publishing:
        # Publishing an index that admits it is incomplete is still publishing
        # an incomplete release record. Cut and verify the agent release first.
        _fail(
            f"no --agent-checksums for {args.agent_tag}; publish and verify the "
            "agent release before releasing the application"
        )
    else:
        # Saying so is the point: an index that quietly omitted the agent would
        # read as a complete release record for a product that ships one.
        component["status"] = "pending"
        component["artifacts"] = []
        component["note"] = (
            "The agent release for this version was not published when this index "
            "was generated. Verify it from its own release tag."
        )
    return component


def _gates(values: List[str]) -> List[dict]:
    gates: List[dict] = []
    for value in values or []:
        parts = value.split("|")
        if len(parts) != 3:
            _fail(f"--gate expects name|status|detail, got {value!r}")
        name, status, detail = (part.strip() for part in parts)
        if not name or not detail:
            _fail(f"--gate needs a name and a detail, got {value!r}")
        if status not in GATE_STATUSES:
            _fail(f"--gate status {status!r} is not one of {', '.join(GATE_STATUSES)}")
        gates.append({"name": name, "status": status, "detail": detail})
    return gates


def _reports(values: List[str]) -> List[dict]:
    reports: List[dict] = []
    for value in values or []:
        name, location = _split_pair(value, "--report")
        if not location.startswith("https://"):
            _fail(f"--report location must be an https URL, got {location!r}")
        reports.append({"name": name, "location": location})
    return reports


def _build_index(args: argparse.Namespace) -> dict:
    publishing = args.mode == "publish"

    if not VERSION_RE.fullmatch(args.version):
        _fail(f"--version {args.version!r} is not a release version")
    if args.tag != f"v{args.version}":
        _fail(f"--tag {args.tag!r} does not match --version {args.version!r}")
    if not COMMIT_RE.fullmatch(args.commit):
        _fail(f"--commit {args.commit!r} is not a full 40 character commit sha")
    if not REPOSITORY_RE.fullmatch(args.repository):
        _fail(f"--repository {args.repository!r} is not owner/name")
    if publishing and not args.attestations:
        _fail("--attestations is required when publishing")

    components = _image_components(args, publishing)
    agent = _agent_component(args, publishing)
    if agent:
        components.append(agent)

    index = {
        "schema": SCHEMA,
        "mode": args.mode,
        "product": PRODUCT,
        "version": args.version,
        "tag": args.tag,
        "source": {
            "repository": args.repository,
            "commit": args.commit,
            "tag": args.tag,
            "url": f"https://github.com/{args.repository}/tree/{args.commit}",
        },
        "build": {
            "workflow": args.workflow,
            "run_id": args.run_id,
            "run_url": (
                f"https://github.com/{args.repository}/actions/runs/{args.run_id}"
                if args.run_id
                else None
            ),
        },
        "components": components,
        "security_gates": _gates(args.gate),
        "reports": _reports(args.report),
    }
    return index


def _markdown_images(images: List[dict], mode: str, repository: str) -> List[str]:
    """Render the container image sections of the public summary."""
    if not images:
        return []

    lines = ["### Container images", ""]
    if mode == "publish":
        lines += ["| Image | Digest | Tags |", "| --- | --- | --- |"]
        for image in images:
            tags = ", ".join(f"`{tag}`" for tag in image["tags"])
            lines.append(f"| `{image['repository']}` | `{image['digest']}` | {tags} |")
        lines += [
            "",
            "Tags move between releases; digests do not. Deploy the digest:",
            "",
            "```sh",
        ]
        lines += [f"docker pull {image['pull_by_digest']}" for image in images]
        lines += ["```", ""]
    else:
        lines += [f"- `{image['repository']}` built, not pushed" for image in images]
        lines.append("")

    lines += ["### Image SBOMs", ""]
    for image in images:
        sbom = image["sbom"]
        lines.append(
            f"- `{sbom['file']}` ({sbom['format']} {sbom['spec_version']}) "
            f"for `{image['name']}`"
        )
    lines.append("")

    if mode == "publish" and images[0]["attestations"]:
        lines += [
            "### Verifying an image",
            "",
            "```sh",
            f"gh attestation verify oci://{images[0]['pull_by_digest']} \\",
            f"    --repo {repository}",
            "```",
            "",
            "The same command verifies each image above. It checks the build",
            "provenance and the SBOM attestation, both issued to this repository's",
            "release workflow through GitHub OIDC. There is no long lived signing",
            "key to distribute or rotate.",
            "",
        ]
    return lines


def _markdown_agent(agent: dict) -> List[str]:
    """Render the fleet agent section of the public summary."""
    lines = ["### Fleet agent", ""]
    if agent["status"] != "published":
        lines += [
            f"The agent release `{agent['release_tag']}` was not published when this "
            "index was generated. Verify the agent from its own release tag.",
            "",
        ]
        return lines

    lines += [
        f"Published under `{agent['release_tag']}`: {agent['release_url']}",
        "",
        "| Artifact | SHA-256 |",
        "| --- | --- |",
    ]
    for artifact in agent["artifacts"]:
        lines.append(f"| `{artifact['name']}` | `{artifact['sha256']}` |")
    lines += [
        "",
        f"`{agent['signature']['manifest']}` is signed with keyless Sigstore. "
        f"Verify it with `{agent['signature']['signature']}` and "
        f"`{agent['signature']['certificate']}` from that release before "
        "trusting the checksums above.",
        "",
    ]
    return lines


def _markdown(index: dict) -> str:
    """Render the public summary.

    Everything here is derived from the validated index, so the summary cannot
    describe a component the record does not contain."""
    version = index["version"]
    repository = index["source"]["repository"]
    lines: List[str] = []

    if index["mode"] != "publish":
        lines += [
            f"## Release validation for {PRODUCT} {version}",
            "",
            "This is a validation run. No image, tag, release, or attestation was",
            "published.",
            "",
        ]
    else:
        lines += [f"## {PRODUCT} {version} release index", ""]

    lines += [
        f"- Source: `{repository}` at commit `{index['source']['commit']}`",
        f"- Release tag: `{index['tag']}`",
    ]
    if index["build"]["run_url"]:
        lines.append(f"- Built by: {index['build']['run_url']}")
    lines.append("")

    images = [c for c in index["components"] if c["kind"] == "container-image"]
    lines += _markdown_images(images, index["mode"], repository)

    agent = next((c for c in index["components"] if c["kind"] == "release-archive"), None)
    if agent:
        lines += _markdown_agent(agent)

    if index["security_gates"]:
        lines += ["### Security gates", "", "| Gate | Status | Detail |", "| --- | --- | --- |"]
        for gate in index["security_gates"]:
            lines.append(f"| {gate['name']} | {gate['status']} | {gate['detail']} |")
        lines.append("")

    if index["reports"]:
        lines += ["### Reports", ""]
        for report in index["reports"]:
            lines.append(f"- [{report['name']}]({report['location']})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    """Validate the release inputs and write the index, or fail loudly."""
    parser = argparse.ArgumentParser(description="Build the public release index.")
    parser.add_argument("--mode", required=True, choices=("publish", "validate"))
    parser.add_argument("--version", required=True, help="release version, e.g. 1.0.0")
    parser.add_argument("--tag", required=True, help="release tag, e.g. v1.0.0")
    parser.add_argument("--commit", required=True, help="full 40 character source commit")
    parser.add_argument("--repository", required=True, help="owner/name of the source repository")
    parser.add_argument("--registry", required=True, help="container registry host")
    parser.add_argument("--owner", required=True, help="registry namespace owning the packages")
    parser.add_argument("--sbom-spec-version", required=True, help="expected CycloneDX spec version")
    parser.add_argument("--workflow", required=True, help="workflow path that produced the release")
    parser.add_argument("--run-id", default="", help="workflow run id")
    parser.add_argument(
        "--image-ref",
        action="append",
        default=[],
        metavar="NAME=REFERENCE",
        help="image reference that was built and scanned",
    )
    parser.add_argument(
        "--image-digest",
        action="append",
        default=[],
        metavar="NAME=sha256:...",
        help="immutable digest of a published image",
    )
    parser.add_argument(
        "--image-tags",
        action="append",
        default=[],
        metavar="NAME=tag[,tag]",
        help="tags a published image was pushed under",
    )
    parser.add_argument(
        "--image-sbom",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="CycloneDX SBOM generated from that image",
    )
    parser.add_argument(
        "--attestations",
        default="",
        help="comma separated attestation kinds issued for every published image",
    )
    parser.add_argument("--agent-tag", default="", help="agent release tag to reference")
    parser.add_argument("--agent-version", default="", help="agent release version, e.g. v1.0.0")
    parser.add_argument(
        "--agent-checksums",
        default="",
        help="agent release checksum manifest to consume, when it is published",
    )
    parser.add_argument(
        "--gate",
        action="append",
        default=[],
        metavar="NAME|STATUS|DETAIL",
        help="security gate this release ran",
    )
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="NAME=URL",
        help="link to a large report rather than copying it into the index",
    )
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-markdown", required=True, type=Path)
    args = parser.parse_args()

    args.attestations = [part.strip() for part in args.attestations.split(",") if part.strip()]

    index = _build_index(args)

    args.out_json.write_text(json.dumps(index, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    args.out_markdown.write_text(_markdown(index), encoding="utf-8")

    published = [c["name"] for c in index["components"]]
    print(
        f"release-index: {args.mode} index for {args.version} "
        f"({', '.join(published)}) written to {args.out_json.name} and "
        f"{args.out_markdown.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
