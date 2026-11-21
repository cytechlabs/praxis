"""A sandboxed native APT for tests: real apt-get, apt and dpkg-query.

Each ``NativeApt`` owns private APT state, a private dpkg database and a
private source list, configured through ``APT_CONFIG``, so tests refresh and
list real APT metadata without touching the host or needing root. Local HTTP
servers answer 401 and 404 for sources that must fail to refresh.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _Respond(BaseHTTPRequestHandler):
    status = 401

    def do_GET(self):  # noqa: N802
        self.send_response(self.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET  # noqa: N815

    def log_message(self, *args):  # pylint: disable=arguments-differ
        """Keep the test output quiet by dropping the access log."""
        return None


def _serve(status):
    handler = type("H", (_Respond,), {"status": status})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def flat_repo(path, package, version, suite):
    os.makedirs(path, exist_ok=True)
    index = (
        f"Package: {package}\nVersion: {version}\nArchitecture: all\n"
        "Maintainer: t <t@example.com>\nInstalled-Size: 1\n"
        f"Filename: ./{package}.deb\nSize: 1\nSHA256: {'0' * 64}\nDescription: d\n"
    )
    with open(os.path.join(path, "Packages"), "w", encoding="utf-8") as fh:
        fh.write(index)
    digest = hashlib.sha256(index.encode()).hexdigest()
    with open(os.path.join(path, "Release"), "w", encoding="utf-8") as fh:
        fh.write(
            f"Origin: t\nSuite: {suite}\nDate: Mon, 01 Jan 2024 00:00:00 UTC\n"
            f"Architectures: all\nSHA256:\n {digest} {len(index)} Packages\n"
        )


class NativeApt:
    """A sandboxed APT: real apt-get/apt/dpkg-query, private state and sources."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="pra435-apt-")
        for sub in (
            "state/lists/partial",
            "cache/archives/partial",
            "etc/sources.list.d",
            "etc/trusted.gpg.d",
            "etc/apt.conf.d",
            "dpkg",
        ):
            os.makedirs(os.path.join(self.root, sub))
        status = os.path.join(self.root, "dpkg", "status")
        with open(status, "w", encoding="utf-8") as fh:
            for name in ("pra435-demo", "pra435-sec"):
                fh.write(
                    f"Package: {name}\nStatus: install ok installed\n"
                    "Priority: optional\nSection: misc\nInstalled-Size: 1\n"
                    "Maintainer: t <t@example.com>\nArchitecture: all\n"
                    "Version: 1.0\nDescription: d\n\n"
                )
        flat_repo(f"{self.root}/good", "pra435-demo", "2.0", "stable")
        flat_repo(f"{self.root}/sec", "pra435-sec", "2.0", "stable-security")
        flat_repo(f"{self.root}/unsigned", "pra435-other", "1.0", "unsigned")
        self.unauthorized = _serve(401)
        self.missing = _serve(404)
        conf = f"{self.root}/apt.conf"
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""
                    Dir "/";
                    Dir::Etc "{self.root}/etc";
                    Dir::Etc::sourcelist "{self.root}/etc/sources.list";
                    Dir::Etc::sourceparts "{self.root}/etc/sources.list.d";
                    Dir::Etc::trusted "{self.root}/etc/none.gpg";
                    Dir::Etc::trustedparts "{self.root}/etc/trusted.gpg.d";
                    Dir::State "{self.root}/state";
                    Dir::State::lists "{self.root}/state/lists";
                    Dir::State::status "{status}";
                    Dir::Cache "{self.root}/cache";
                    APT::Sandbox::User "";
                    """))
        self.env = dict(
            os.environ,
            APT_CONFIG=conf,
            DPKG_ADMINDIR=os.path.join(self.root, "dpkg"),
        )
        self.set_sources()

    def set_sources(self, *extra):
        lines = [
            f"deb [trusted=yes] file:{self.root}/good ./",
            f"deb [trusted=yes] file:{self.root}/sec ./",
        ]
        lines.extend(extra)
        with open(f"{self.root}/etc/sources.list", "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def unentitled_source(self):
        return f"deb [trusted=yes] http://127.0.0.1:{self.unauthorized.server_port}/ent trixie main"

    def removed_source(self):
        return f"deb [trusted=yes] http://127.0.0.1:{self.missing.server_port}/old trixie main"

    def disabled_source(self):
        return f"# {self.unentitled_source()}"

    def unsigned_source(self):
        return f"deb file:{self.root}/unsigned ./"

    def run(self, command):
        proc = subprocess.run(
            ["/bin/sh", "-c", command],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "status": "success" if proc.returncode == 0 else "warning",
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode,
        }

    def candidates(self):
        out = self.run("apt list --upgradable 2>/dev/null")["stdout"]
        found = {}
        for line in out.splitlines():
            if "[upgradable from:" in line:
                name = line.split("/", 1)[0]
                found[name] = line.split()[1]
        return found

    def close(self):
        self.unauthorized.shutdown()
        self.missing.shutdown()
        shutil.rmtree(self.root, ignore_errors=True)


class NativeSSH:
    def __init__(self, apt):
        self.apt = apt
        self.commands = []

    def _run(self, command):
        self.commands.append(command)
        return self.apt.run(command)

    def execute_command(self, system_id, command, timeout=None, user_id=None):
        return self._run(command)

    def execute_privileged_command(
        self, system_id, command, timeout=None, user_id=None
    ):
        return self._run(command)


needs_apt = pytest.mark.skipif(
    not (
        shutil.which("apt-get") and shutil.which("apt") and shutil.which("dpkg-query")
    ),
    reason="native APT tooling is not available",
)
