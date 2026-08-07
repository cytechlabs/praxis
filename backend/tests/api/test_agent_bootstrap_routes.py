"""PRA-154 slice #1d-b: bootstrap script + agent download routes."""

from __future__ import annotations

from unittest.mock import patch

import pytest

# ---------------------------------------------------------------- bootstrap.sh


def test_bootstrap_script_substitutes_public_url(client, monkeypatch):
    monkeypatch.setenv("PRAXIS_PUBLIC_URL", "https://praxis.example.com")
    res = client.get("/agent/bootstrap.sh")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/x-shellscript")
    assert "attachment" in res.headers["content-disposition"]
    assert 'filename="bootstrap.sh"' in res.headers["content-disposition"]
    body = res.text
    assert "__PRAXIS_DEFAULT_URL__" not in body
    assert "https://praxis.example.com" in body
    assert "set -euo pipefail" in body


def test_bootstrap_script_strips_trailing_slash_in_substitution(client, monkeypatch):
    monkeypatch.setenv("PRAXIS_PUBLIC_URL", "https://praxis.example.com/")
    res = client.get("/agent/bootstrap.sh")
    assert res.status_code == 200
    body = res.text
    assert "https://praxis.example.com/agent/bootstrap.sh" not in body
    assert "https://praxis.example.com" in body


def test_bootstrap_script_returns_500_when_public_url_unset(client, monkeypatch):
    monkeypatch.delenv("PRAXIS_PUBLIC_URL", raising=False)
    res = client.get("/agent/bootstrap.sh")
    assert res.status_code == 500


def test_bootstrap_script_is_anonymous(client, monkeypatch):
    """No Authorization header — should still work because the
    JWTAuthMiddleware allow-list exempts the path."""
    monkeypatch.setenv("PRAXIS_PUBLIC_URL", "https://praxis.example.com")
    res = client.get("/agent/bootstrap.sh")
    assert res.status_code == 200


# ---------------------------------------------------------------- download proxy
#
# The agent release pipeline ships per-arch tarballs and one shared
# checksums.txt. The control plane exposes canonical names
# (``agent.tar.gz``, ``agent.tar.gz.sha256``) so the host doesn't
# learn the version; the route translates those to the real
# release-asset names internally and synthesizes a single-line
# checksum file pointing at ``agent.tar.gz``.

# Match the constants in agent_bootstrap.py — kept in sync by hand
# rather than imported because changing the version pin should also
# require touching the tests.
_RELEASE_VERSION = "v0.0.0-rc1"


def _real_tarball(arch: str) -> str:
    return f"praxis-agent-{_RELEASE_VERSION}-linux-{arch}.tar.gz"


@pytest.fixture
def local_artifact_dir(tmp_path, monkeypatch):
    """Stage a fake local artifact tree that mirrors the release
    output: flat directory containing per-arch tarballs and one
    shared checksums.txt."""
    base = tmp_path / "agent-artifacts"
    base.mkdir()
    digests = {
        "amd64": "0" * 63 + "a",
        "arm64": "0" * 63 + "b",
    }
    for arch in ("amd64", "arm64"):
        (base / _real_tarball(arch)).write_bytes(b"FAKE_TARBALL_" + arch.encode())
    (base / "checksums.txt").write_text(
        f"{digests['amd64']}  {_real_tarball('amd64')}\n"
        f"{digests['arm64']}  {_real_tarball('arm64')}\n"
    )
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(base))
    return base


def test_download_serves_local_tarball_under_canonical_name(client, local_artifact_dir):
    res = client.get("/agent/download/amd64/agent.tar.gz")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/octet-stream")
    assert res.content == b"FAKE_TARBALL_amd64"


def test_download_synthesizes_per_arch_checksum_with_canonical_filename(
    client, local_artifact_dir
):
    res = client.get("/agent/download/arm64/agent.tar.gz.sha256")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/plain")
    line = res.text.strip()
    digest, fname = line.split(maxsplit=1)
    assert len(digest) == 64
    assert fname == "agent.tar.gz"
    # Specifically: arm64 digest, not amd64.
    assert digest.endswith("b")


def test_download_anonymous(client, local_artifact_dir):
    res = client.get("/agent/download/amd64/agent.tar.gz")
    assert res.status_code == 200


def test_download_rejects_unknown_arch(client, local_artifact_dir):
    res = client.get("/agent/download/sparc64/agent.tar.gz")
    assert res.status_code == 404


def test_download_rejects_unknown_filename(client, local_artifact_dir):
    res = client.get("/agent/download/amd64/passwd")
    assert res.status_code == 404


def test_download_rejects_versioned_real_name(client, local_artifact_dir):
    """Only canonical names are exposed. The real versioned filename
    must NOT be reachable — that keeps version bumps server-side."""
    res = client.get(f"/agent/download/amd64/{_real_tarball('amd64')}")
    assert res.status_code == 404


def test_download_rejects_path_traversal(client, local_artifact_dir):
    res = client.get("/agent/download/amd64/../etc/passwd")
    assert res.status_code in (400, 404)


def test_download_falls_back_to_github_when_local_missing(
    client, monkeypatch, tmp_path
):
    """Empty local dir -> the route streams the REAL versioned asset
    name from the pinned GitHub Release."""
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(tmp_path / "empty"))

    class _FakeResp:
        def __init__(self, body: bytes):
            self._body = body
            self._idx = 0
            self.headers = {"Content-Length": str(len(body))}

        def read(self, n=None):
            if n is None:
                rest = self._body[self._idx :]
                self._idx = len(self._body)
                return rest
            chunk = self._body[self._idx : self._idx + n]
            self._idx += len(chunk)
            return chunk

        def close(self):
            pass

    captured = {}

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResp(b"GH_TARBALL")

    with patch("urllib.request.urlopen", new=_fake_urlopen):
        res = client.get("/agent/download/amd64/agent.tar.gz")
    assert res.status_code == 200
    assert res.content == b"GH_TARBALL"
    assert f"agent-{_RELEASE_VERSION}" in captured["url"]
    assert captured["url"].endswith(f"/{_real_tarball('amd64')}")


def test_download_checksum_falls_back_to_github_when_local_missing(
    client, monkeypatch, tmp_path
):
    """Checksum synthesis must work in the GitHub-fallback path: the
    route fetches checksums.txt from the release, finds the matching
    line, and rewrites the filename to ``agent.tar.gz``."""
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(tmp_path / "empty"))

    digest = "f" * 64
    body = (
        f"{digest}  {_real_tarball('amd64')}\n"
        f"{'e' * 64}  {_real_tarball('arm64')}\n"
    ).encode("utf-8")

    class _FakeResp:
        def __init__(self, b):
            self._b = b
            self._idx = 0
            self.headers = {"Content-Length": str(len(b))}

        def read(self, n=None):
            if n is None:
                rest = self._b[self._idx :]
                self._idx = len(self._b)
                return rest
            chunk = self._b[self._idx : self._idx + n]
            self._idx += len(chunk)
            return chunk

        def close(self):
            pass

    def _fake_urlopen(req, timeout=None):
        if req.full_url.endswith("/checksums.txt"):
            return _FakeResp(body)
        raise AssertionError(f"unexpected fetch: {req.full_url}")

    with patch("urllib.request.urlopen", new=_fake_urlopen):
        res = client.get("/agent/download/amd64/agent.tar.gz.sha256")
    assert res.status_code == 200
    line = res.text.strip()
    out_digest, out_name = line.split(maxsplit=1)
    assert out_digest == digest
    assert out_name == "agent.tar.gz"


def test_download_returns_502_when_github_fails(client, monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(tmp_path / "empty"))
    import urllib.error

    def _boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    with patch("urllib.request.urlopen", new=_boom):
        res = client.get("/agent/download/amd64/agent.tar.gz")
    assert res.status_code == 502


def test_checksum_returns_502_when_release_lacks_matching_line(
    client, tmp_path, monkeypatch
):
    """checksums.txt without our arch's tarball line is a release-
    pipeline contract violation. Surface it loudly instead of
    returning a wrong checksum."""
    base = tmp_path / "broken-artifacts"
    base.mkdir()
    (base / "checksums.txt").write_text("deadbeef  some-other-asset.tar.gz\n")
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(base))
    res = client.get("/agent/download/amd64/agent.tar.gz.sha256")
    assert res.status_code == 502
