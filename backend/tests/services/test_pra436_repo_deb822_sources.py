"""PRA-436: APT source parsing keeps file boundaries and honours Enabled.

The fixture under tests/fixtures/apt_sources/mixed is a mixed .list/.sources
tree whose files deliberately lack trailing newlines. expected_inventory.json
is the inventory native APT reports for that tree, and is reusable by
integration tests that need a known enabled/disabled source set.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.services.repo_service import (
    APT_FILE_MARKER,
    RepoService,
    apt_list_repos_command,
)

SOURCE_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "apt_sources" / "mixed"
)
EXPECTED = json.loads((SOURCE_FIXTURE / "expected_inventory.json").read_text())


@pytest.fixture(name="fixture_root")
def fixture_root_fixture(tmp_path):
    """Copy of the fixture tree whose files have no trailing newline.

    The committed files end in a newline so repository whitespace hooks leave
    them alone; the missing final newline, which is what let adjacent files
    merge, is reproduced here.
    """
    root = tmp_path / "mixed"
    shutil.copytree(SOURCE_FIXTURE, root)
    for path in (root / "etc" / "apt").rglob("*"):
        if path.is_file():
            path.write_bytes(path.read_bytes().rstrip(b"\n"))
    return root


def _service() -> RepoService:
    return RepoService.__new__(RepoService)


def _listing(root: Path) -> str:
    """Run the production listing command against a fixture tree."""
    result = subprocess.run(
        ["sh", "-c", apt_list_repos_command(str(root / "etc" / "apt"))],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _tuples(entries):
    """Expand parsed entries to (type, url, suite, component) tuples."""
    out = set()
    for e in entries:
        comps = e["components"].split() or [""]
        for comp in comps:
            out.add((e["type"], e["url"].rstrip("/"), e["distribution"], comp))
    return out


def _expected(key):
    return {tuple(t) for t in EXPECTED[key]}


def test_listing_marks_every_file_in_apt_read_order(fixture_root):
    out = _listing(fixture_root)
    markers = [
        line[len(APT_FILE_MARKER) :].rsplit("/", 1)[-1]
        for line in out.splitlines()
        if line.startswith(APT_FILE_MARKER)
    ]
    assert markers == [
        "sources.list",
        "10-updates.sources",
        "20-security.sources",
        "30-enterprise.sources",
        "40-no-subscription.sources",
        "50-multi.sources",
        "60-extra.list",
    ]
    # Ignored names are filtered before their contents are read.
    assert "ignored.example.test" not in out


def test_active_inventory_matches_native_apt_expectation(fixture_root):
    active, _ = _service()._parse_apt_inventory(_listing(fixture_root))
    assert _tuples(active) == _expected("active")


def test_disabled_entries_are_explicit_and_never_active(fixture_root):
    active, disabled = _service()._parse_apt_inventory(_listing(fixture_root))
    assert _tuples(disabled) == _expected("disabled")
    assert all(e["enabled"] for e in active)
    assert all(not e["enabled"] for e in disabled)
    assert not _tuples(active) & _tuples(disabled)


def test_entries_carry_their_source_file(fixture_root):
    active, disabled = _service()._parse_apt_inventory(_listing(fixture_root))
    by_url = {e["url"]: e for e in active + disabled}
    assert by_url["http://security.example.test/debian-security"]["file_path"].endswith(
        "/20-security.sources"
    )
    assert by_url["https://enterprise.example.test/pve"]["file_path"].endswith(
        "/30-enterprise.sources"
    )
    assert by_url["http://list-only.example.test/debian"]["file_path"].endswith(
        "/60-extra.list"
    )


def test_files_without_trailing_newline_do_not_merge_stanzas():
    out = (
        f"{APT_FILE_MARKER}/etc/apt/sources.list.d/a.sources\n"
        "Types: deb\nURIs: http://a.test/d\nSuites: s1\nComponents: main"
        f"\n{APT_FILE_MARKER}/etc/apt/sources.list.d/b.sources\n"
        "Types: deb\nURIs: http://b.test/d\nSuites: s2\nComponents: extra"
    )
    active, _ = _service()._parse_apt_inventory(out)
    assert _tuples(active) == {
        ("deb", "http://a.test/d", "s1", "main"),
        ("deb", "http://b.test/d", "s2", "extra"),
    }


def test_missing_marker_newline_would_have_merged_files(fixture_root):
    """Regression for the unseparated concatenation the old command produced."""
    legacy = "".join(
        p.read_text()
        for p in sorted((fixture_root / "etc/apt/sources.list.d").glob("*.sources"))
    )
    # The old parser split only on blank lines; show the inputs really do run
    # together without a blank line between files.
    assert "Components: main contribTypes: deb" in legacy


@pytest.mark.parametrize(
    "value,enabled",
    [
        (None, True),
        ("yes", True),
        ("true", True),
        ("1", True),
        ("no", False),
        ("No", False),
        ("WITHOUT", False),
        ("FALSE", False),
        ("0", False),
        ("00", False),
        ("0x0", False),
        ("01", True),
        ("2", True),
        ("-1", True),
        ("08", True),
        ("off", False),
        ("without", False),
        ("disable", False),
        ("disabled", True),
        ("enable", True),
        ("maybe", True),
    ],
)
def test_enabled_semantics(value, enabled):
    field = "" if value is None else f"Enabled: {value}\n"
    text = f"Types: deb\nURIs: http://x.test/d\nSuites: s\nComponents: main\n{field}"
    entries = _service()._parse_deb822(text)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["enabled"] is enabled


def test_multivalue_and_continuation_fields_expand_like_apt():
    text = (
        "Types: deb deb-src\n"
        "URIs: http://a.test/u http://b.test/u\n"
        "Suites: one\n two\n"
        "Components: main\n universe\n"
    )
    entries = _service()._parse_deb822(text)
    assert len(entries) == 2 * 2 * 2
    assert {e["components"] for e in entries} == {"main universe"}
    assert {e["distribution"] for e in entries} == {"one", "two"}


def test_comments_and_blank_lines_inside_a_file():
    text = (
        "# lead comment\n"
        "Types: deb\n# inside\nURIs: http://a.test/u\nSuites: s\nComponents: c\n\n"
        "# between stanzas\n\n"
        "Types: deb\nURIs: http://b.test/u\nSuites: s\nComponents: c\nEnabled: no\n"
    )
    entries = _service()._parse_deb822(text)
    assert [(e["url"], e["enabled"]) for e in entries] == [
        ("http://a.test/u", True),
        ("http://b.test/u", False),
    ]


def test_classic_list_options_comments_and_disabled_lines():
    text = (
        "# comment\n"
        "deb [arch=amd64 signed-by=/k.gpg] http://a.test/d s main contrib # note\n"
        "#deb http://off.test/d s main\n"
        "deb-src http://a.test/d s main"
    )
    entries = _service()._parse_one_line(text, "/etc/apt/sources.list")
    assert [
        (e["type"], e["url"], e["distribution"], e["components"]) for e in entries
    ] == [
        ("deb", "http://a.test/d", "s", "main contrib"),
        ("deb-src", "http://a.test/d", "s", "main"),
    ]


def test_invalid_part_names_are_ignored():
    out = (
        f"{APT_FILE_MARKER}/etc/apt/sources.list.d/bad name.list\n"
        "deb http://x.test/d s main\n"
    )
    active, disabled = _service()._parse_apt_inventory(out)
    assert active == [] and disabled == []


def test_list_repos_reports_active_and_disabled_separately(fixture_root):
    svc = _service()
    system = MagicMock(hostname="h")
    svc._get_system_or_raise = lambda _id: system
    svc._get_pkg_manager = lambda _s: "apt"
    svc.ssh_service = MagicMock()
    svc.ssh_service.execute_command.return_value = {
        "status": "success",
        "stdout": _listing(fixture_root),
    }
    svc.db = MagicMock()
    svc.db.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
        []
    )
    result = svc.list_repos(1)
    assert _tuples(result["detected_repos"]) == _expected("active")
    assert _tuples(result["disabled_repos"]) == _expected("disabled")


@pytest.mark.skipif(shutil.which("apt-get") is None, reason="apt-get not available")
def test_parser_matches_native_apt_on_fixture(fixture_root):
    etc = fixture_root / "etc" / "apt"
    with tempfile.TemporaryDirectory() as tmp:
        out = subprocess.run(
            [
                "apt-get",
                "update",
                "--print-uris",
                "-o",
                f"Dir::Etc::sourcelist={etc}/sources.list",
                "-o",
                f"Dir::Etc::sourceparts={etc}/sources.list.d",
                "-o",
                f"Dir::State::lists={tmp}",
                "-o",
                f"Dir::Cache={tmp}",
                "-o",
                "APT::Architecture=amd64",
                "-o",
                "APT::Architectures::=amd64",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    import re

    native = set()
    pat = re.compile(
        r"^'(.+?)/dists/([^/]+)/([^/]+)/(?:binary-[^/]+/Packages|source/Sources)\.\w+'"
    )
    for line in out.splitlines():
        token = line.split()[0] if line.strip() else ""
        m = pat.match(token)
        if m:
            kind = "deb-src" if "/source/Sources" in token else "deb"
            native.add((kind, m.group(1), m.group(2), m.group(3)))
        elif token.startswith("'") and "/./Packages." in token:
            native.add(("deb", token[1:].split("/./Packages.")[0], "./", ""))
    active, _ = _service()._parse_apt_inventory(_listing(fixture_root))
    assert _tuples(active) == native


PART_NAMES_ACTIVE = [
    "a.sources",
    "A-b_c.sources",
    "a:b.sources",
    "-x.sources",
    "_x.sources",
    "1.sources",
    "a.dist-upgrade.sources",
    "a..sources",
    "a.list",
    "a:b.list",
]
PART_NAMES_IGNORED = [
    ".hidden.sources",
    ".sources",
    "a+b.sources",
    "a~.sources",
    "a b.sources",
    "a,b.sources",
    "@x.sources",
    "a.sources.save",
    "a.sources~",
    "a.sources.disabled",
    "a.SOURCES",
    "a.source",
    "sources",
    "a.list.bak",
    ".hidden.list",
    "a.LIST",
]
ENABLED_FALSE = [
    "no",
    "false",
    "0",
    "00",
    "0x0",
    "off",
    "without",
    "disable",
    "No",
    "OFF",
]
ENABLED_TRUE = [
    "yes",
    "true",
    "1",
    "01",
    "2",
    "-1",
    "0x1",
    "08",
    "on",
    "with",
    "enable",
    "enabled",
    "disabled",
    "maybe",
    "y",
    "n",
]


def _write_part(root: Path, name: str, host: str, enabled=None):
    parts = root / "etc" / "apt" / "sources.list.d"
    parts.mkdir(parents=True, exist_ok=True)
    if name.endswith(".list") or name.endswith(".list.bak") or name.endswith(".LIST"):
        body = f"deb http://{host}.test/d s main\n"
    else:
        extra = "" if enabled is None else f"Enabled: {enabled}\n"
        body = f"Types: deb\nURIs: http://{host}.test/d\nSuites: s\nComponents: main\n{extra}"
    (parts / name).write_text(body)


def _native_hosts(root: Path):
    """Hosts of the sources native APT treats as active under root."""
    import re

    etc = root / "etc" / "apt"
    (etc / "sources.list").touch()
    with tempfile.TemporaryDirectory() as tmp:
        out = subprocess.run(
            [
                "apt-get",
                "update",
                "--print-uris",
                "-o",
                f"Dir::Etc::sourcelist={etc}/sources.list",
                "-o",
                f"Dir::Etc::sourceparts={etc}/sources.list.d",
                "-o",
                f"Dir::State::lists={tmp}",
                "-o",
                f"Dir::Cache={tmp}",
                "-o",
                "APT::Architecture=amd64",
                "-o",
                "APT::Architectures::=amd64",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return set(re.findall(r"'http://(h\d+)\.test/", out))


def _parsed_hosts(root: Path):
    active, _ = _service()._parse_apt_inventory(_listing(root))
    return {e["url"].split("//")[1].split(".")[0] for e in active}


def test_part_names_follow_apt_filename_rules(tmp_path):
    names = PART_NAMES_ACTIVE + PART_NAMES_IGNORED
    hosts = {}
    for i, name in enumerate(names):
        hosts[name] = f"h{i}"
        _write_part(tmp_path, name, f"h{i}")
    got = {n for n, h in hosts.items() if h in _parsed_hosts(tmp_path)}
    assert got == set(PART_NAMES_ACTIVE)
    listing = _listing(tmp_path)
    for name in PART_NAMES_IGNORED:
        assert f"{hosts[name]}.test" not in listing, name


@pytest.mark.skipif(shutil.which("apt-get") is None, reason="apt-get not available")
def test_part_names_match_native_apt(tmp_path):
    names = [
        n
        for n in PART_NAMES_ACTIVE + PART_NAMES_IGNORED
        if not n.endswith(".list.bak")
        and not n.endswith(".LIST")
        and n != ".hidden.list"
    ]
    hosts = {}
    for i, name in enumerate(names):
        hosts[name] = f"h{i}"
        _write_part(tmp_path, name, f"h{i}")
    native = _native_hosts(tmp_path)
    assert {n for n, h in hosts.items() if h in native} == set(PART_NAMES_ACTIVE)
    assert _parsed_hosts(tmp_path) == native


def test_enabled_values_filter_active_inventory(tmp_path):
    values = ENABLED_FALSE + ENABLED_TRUE
    for i, value in enumerate(values):
        _write_part(tmp_path, f"e{i:02d}.sources", f"h{i}", value)
    parsed = _parsed_hosts(tmp_path)
    assert {f"h{i}" for i, v in enumerate(values) if v in ENABLED_TRUE} == parsed


@pytest.mark.skipif(shutil.which("apt-get") is None, reason="apt-get not available")
def test_enabled_values_match_native_apt(tmp_path):
    values = ENABLED_FALSE + ENABLED_TRUE
    for i, value in enumerate(values):
        _write_part(tmp_path, f"e{i:02d}.sources", f"h{i}", value)
    native = _native_hosts(tmp_path)
    assert {f"h{i}" for i, v in enumerate(values) if v in ENABLED_TRUE} == native
    assert _parsed_hosts(tmp_path) == native


def test_part_order_is_byte_order_and_deterministic(tmp_path):
    for name in [
        "b.list",
        "B.list",
        "10-x.sources",
        "a.sources",
        "_z.list",
        "A.sources",
    ]:
        _write_part(tmp_path, name, "h0")
    first = _listing(tmp_path)
    names = [
        line[len(APT_FILE_MARKER) :].rsplit("/", 1)[-1]
        for line in first.splitlines()
        if line.startswith(APT_FILE_MARKER)
    ]
    assert names == sorted(
        ["sources.list"] * 0
        + ["b.list", "B.list", "10-x.sources", "a.sources", "_z.list", "A.sources"],
        key=lambda n: n.encode(),
    )
    assert _listing(tmp_path) == first
