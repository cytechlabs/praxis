"""PRA-399: the installed backend package must carry its runtime shell assets.

The backend executes two shell scripts that live inside the ``app`` package:
``_assets/collect-facts.sh`` (piped to a managed host over SSH) and
``_assets/bootstrap.sh`` (served to hosts that enroll an agent). Neither is a
Python module, so both are invisible to ``find_packages()`` and were absent
from the wheel and the source distribution until the packaging metadata
declared them. An installed distribution then failed at the first facts
refresh or agent enrollment.

These tests hold the packaging contract from three sides:

- the declaration side: every asset in the source tree is declared in
  ``setup.py`` and ``MANIFEST.in``, so a new asset cannot ship undeclared;
- the artifact side: a freshly built wheel and source distribution contain the
  assets with bytes identical to the tracked files; and
- the runtime side: the readers resolve their asset through the package
  resource API, so an installed distribution works from any working directory
  with no checkout on disk, and a missing asset raises a stable sanitized
  error instead of a raw filesystem error.
"""

import fnmatch
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from ast import Call, literal_eval, parse, walk
from importlib.util import find_spec
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api.routes import agent_bootstrap
from app.services import ssh_facts_collector_service

BACKEND = Path(__file__).resolve().parents[2]
# The repository checkout root. Nothing at or beneath it may reach the probe's
# import path, otherwise the probe could read assets from the source tree and
# report success for an artifact that never shipped them.
CHECKOUT_ROOT = BACKEND.parent
APP_DIR = BACKEND / "app"
SETUP_PY = BACKEND / "setup.py"
MANIFEST_IN = BACKEND / "MANIFEST.in"

# Runtime assets the backend reads from inside its own package. Anything new
# under an ``_assets`` directory has to be added here and to both packaging
# declarations before it can ship.
BUNDLED_ASSETS = (
    "app/api/routes/_assets/bootstrap.sh",
    "app/services/_assets/collect-facts.sh",
)

# A local setuptools makes an offline, isolation-free build possible. Without
# it the build falls back to pip's isolated backend, which needs an index.
LOCAL_BUILD_BACKEND = (
    find_spec("setuptools") is not None and find_spec("wheel") is not None
)

# Runs under ``-S`` with an explicit import path, so no ``.pth`` file, editable
# install hook, or user site directory can substitute a different ``app``. It
# exits non-zero rather than reporting a package it did not import from the
# temporary installation.
PROBE = """
import hashlib
import os
import sys

def within(path, root):
    return os.path.commonpath([os.path.realpath(path), root]) == root


target = os.path.realpath(os.environ["PRAXIS_PROBE_TARGET"])
checkout = os.path.realpath(os.environ["PRAXIS_PROBE_CHECKOUT"])

if within(target, checkout):
    sys.exit("the temporary installation lies inside the checkout: " + target)

leaked = [entry for entry in sys.path if entry and within(entry, checkout)]
if leaked:
    sys.exit("checkout on the import path: " + repr(leaked))

import app
from app.api.routes import agent_bootstrap
from app.services import ssh_facts_collector_service

resolved = os.path.realpath(app.__file__)
if not within(resolved, target):
    sys.exit("app imported from " + resolved + " instead of " + target)

print("app_root=" + resolved)
print("path_entries=" + str(len(sys.path)))
for name, text in (
    ("bootstrap", agent_bootstrap._load_script()),
    ("collector", ssh_facts_collector_service._read_script()),
):
    print(name + "=" + hashlib.sha256(text.encode("utf-8")).hexdigest())
"""


def _run(cmd, cwd, env=None):
    # check=False on purpose: every caller inspects returncode itself, and the
    # build probe tolerates a non-zero exit when no local build backend exists.
    return subprocess.run(
        [str(part) for part in cmd],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


def _package_and_resource(relative_path):
    """Split ``app/services/_assets/x.sh`` into ``app.services`` and
    ``_assets/x.sh``: the owning package and the path within it."""
    parts = relative_path.split("/")
    boundary = parts.index("_assets")
    return ".".join(parts[:boundary]), "/".join(parts[boundary:])


def _declared_package_data():
    for node in walk(parse(SETUP_PY.read_text(encoding="utf-8"))):
        if isinstance(node, Call) and getattr(node.func, "id", None) == "setup":
            for keyword in node.keywords:
                if keyword.arg == "package_data":
                    return literal_eval(keyword.value)
    return {}


def _manifest_recursive_includes():
    includes = []
    for line in MANIFEST_IN.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("recursive-include "):
            continue
        _, directory, *patterns = line.split()
        includes.append((directory.rstrip("/"), patterns))
    return includes


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _import_path_outside_checkout():
    """This interpreter's import path with the whole checkout removed.

    The probe runs with ``-S``, so it cannot rebuild the path from site
    configuration; it is handed the dependency directories explicitly. Every
    entry equal to or beneath ``CHECKOUT_ROOT`` is dropped here, which covers
    the repository root itself as well as ``backend/`` and any editable-install
    entry inside them. The probe rejects the same set again, so a missed entry
    fails the test rather than silently widening the import path.
    """
    kept = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = Path(entry).resolve()
        if resolved == CHECKOUT_ROOT or CHECKOUT_ROOT in resolved.parents:
            continue
        kept.append(str(resolved))
    return kept


@pytest.fixture(scope="module")
def package_tree(tmp_path_factory):
    """A pristine copy of the packaging inputs. Building here keeps build
    directories and egg-info out of the working tree."""
    root = tmp_path_factory.mktemp("pra399") / "src"
    root.mkdir()
    shutil.copy2(SETUP_PY, root / SETUP_PY.name)
    shutil.copy2(MANIFEST_IN, root / MANIFEST_IN.name)
    shutil.copytree(
        APP_DIR,
        root / "app",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    return root


@pytest.fixture(scope="module")
def wheel_path(package_tree):
    out = package_tree.parent / "dist"
    command = [sys.executable, "-m", "pip", "wheel", "--no-deps", "--quiet", "-w", out]
    if LOCAL_BUILD_BACKEND:
        command.append("--no-build-isolation")
    result = _run(command + ["."], package_tree)
    if result.returncode != 0 and not LOCAL_BUILD_BACKEND:
        pytest.skip(f"no usable build backend: {result.stderr.strip()[-400:]}")
    assert result.returncode == 0, result.stderr
    built = sorted(out.glob("app-*.whl"))
    assert len(built) == 1, f"expected exactly one wheel, got {built}"
    return built[0]


@pytest.fixture(scope="module")
def sdist_path(package_tree):
    if not LOCAL_BUILD_BACKEND:
        pytest.skip("building a source distribution needs a local setuptools")
    out = package_tree.parent / "sdist"
    if find_spec("build") is not None:
        command = [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "-o",
            out,
        ]
    else:
        command = [sys.executable, "setup.py", "--quiet", "sdist", "--dist-dir", out]
    result = _run(command, package_tree)
    assert result.returncode == 0, result.stderr
    built = sorted(out.glob("app-*.tar.gz"))
    assert len(built) == 1, f"expected exactly one sdist, got {built}"
    return built[0]


# --------------------------------------------------------------- declarations


def test_bundled_asset_inventory_matches_the_source_tree():
    """A new runtime asset must join the inventory the other tests enforce."""
    found = sorted(
        path.relative_to(BACKEND).as_posix()
        for path in APP_DIR.rglob("_assets/*")
        if path.is_file()
    )
    assert found == sorted(BUNDLED_ASSETS)


def test_setup_declares_every_bundled_asset_as_package_data():
    declared = _declared_package_data()
    for asset in BUNDLED_ASSETS:
        package, resource = _package_and_resource(asset)
        patterns = declared.get(package, [])
        assert any(
            fnmatch.fnmatch(resource, pattern) for pattern in patterns
        ), f"{asset} is not covered by package_data[{package!r}]={patterns!r}"


def test_manifest_declares_every_bundled_asset():
    includes = _manifest_recursive_includes()
    for asset in BUNDLED_ASSETS:
        directory, name = asset.rsplit("/", 1)
        assert any(
            included == directory
            and any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
            for included, patterns in includes
        ), f"{asset} is not covered by a MANIFEST.in recursive-include"


# ------------------------------------------------------------------ artifacts


def test_wheel_ships_every_bundled_asset_unchanged(wheel_path):
    with zipfile.ZipFile(wheel_path) as wheel:
        names = set(wheel.namelist())
        for asset in BUNDLED_ASSETS:
            assert asset in names, f"{asset} missing from {wheel_path.name}"
            assert wheel.read(asset) == (BACKEND / asset).read_bytes()


def test_sdist_ships_every_bundled_asset_unchanged(sdist_path):
    with tarfile.open(sdist_path) as sdist:
        members = {
            name.split("/", 1)[1]: name for name in sdist.getnames() if "/" in name
        }
        for asset in BUNDLED_ASSETS:
            assert asset in members, f"{asset} missing from {sdist_path.name}"
            extracted = sdist.extractfile(members[asset])
            assert extracted is not None
            assert extracted.read() == (BACKEND / asset).read_bytes()


def test_installed_wheel_serves_assets_outside_the_checkout(wheel_path, tmp_path):
    """Install the wheel on its own and read both assets from a working
    directory outside the repository, with nothing from the checkout on the
    import path. This is the acceptance proof for the PRA, so it never skips:
    an ``app`` imported from anywhere but the temporary installation fails."""
    target = (tmp_path / "site").resolve()
    assert CHECKOUT_ROOT not in target.parents, (
        "the temporary installation must sit outside the checkout; " f"got {target}"
    )
    install = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--quiet",
            "--no-index",
            "--target",
            target,
            wheel_path,
        ],
        tmp_path,
    )
    assert install.returncode == 0, install.stderr

    probe = tmp_path / "probe.py"
    probe.write_text(PROBE, encoding="utf-8")

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(target)] + _import_path_outside_checkout())
    env["PRAXIS_PROBE_TARGET"] = str(target)
    env["PRAXIS_PROBE_CHECKOUT"] = str(CHECKOUT_ROOT)
    env.pop("PYTHONSTARTUP", None)
    env.setdefault("DATABASE_URL", "postgresql://praxis:praxis@127.0.0.1:5432/praxis")
    env.setdefault("SECRET_KEY", "packaging-probe-secret")

    # -S keeps site processing out of the child: .pth files, editable-install
    # finders, and the user site directory cannot redirect the import.
    result = _run([sys.executable, "-S", probe], tmp_path, env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    reported = dict(
        line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line
    )
    assert reported["app_root"].startswith(str(target))
    for asset in BUNDLED_ASSETS:
        key = "bootstrap" if asset.endswith("bootstrap.sh") else "collector"
        assert reported[key] == _sha256(
            (BACKEND / asset).read_text(encoding="utf-8")
        ), f"{asset} bytes differ between the installed package and the source tree"


# -------------------------------------------------------------------- readers


def test_readers_resolve_assets_through_the_package_resource_api():
    for module in (agent_bootstrap, ssh_facts_collector_service):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert (
            "resources.files(" in source
        ), f"{module.__name__} must use the resource API"
        assert "__file__" not in source, (
            f"{module.__name__} resolves a path from __file__; installed "
            "distributions have no source tree to walk"
        )


def test_readers_return_the_tracked_asset_bytes():
    assert agent_bootstrap._load_script() == (
        BACKEND / "app/api/routes/_assets/bootstrap.sh"
    ).read_text(encoding="utf-8")
    assert ssh_facts_collector_service._read_script() == (
        BACKEND / "app/services/_assets/collect-facts.sh"
    ).read_text(encoding="utf-8")


def test_collector_raises_a_sanitized_error_when_its_script_is_missing(monkeypatch):
    monkeypatch.setattr(
        ssh_facts_collector_service, "_SCRIPT_NAME", "absent-collector.sh"
    )
    with pytest.raises(ssh_facts_collector_service.SshFactsCollectionError) as raised:
        ssh_facts_collector_service._read_script()
    assert str(raised.value) == "bundled collector script is unavailable"


def test_bootstrap_route_fails_closed_when_its_script_is_missing(monkeypatch):
    monkeypatch.setattr(agent_bootstrap, "_script_cache", None)
    monkeypatch.setattr(agent_bootstrap, "_SCRIPT_NAME", "absent-bootstrap.sh")
    with pytest.raises(HTTPException) as raised:
        agent_bootstrap._load_script()
    assert raised.value.status_code == 500
    assert "absent-bootstrap.sh" not in raised.value.detail
    assert str(BACKEND) not in raised.value.detail
