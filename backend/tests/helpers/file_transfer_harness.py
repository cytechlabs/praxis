"""Real-HTTP harness for download behavior (PRA-429).

Serves the actual file-transfer router over uvicorn, backed by the in-memory
SSH and agent fixtures in ``file_transfer_fakes``. Authentication, the
database and the audit store are replaced with in-memory stand-ins so the
harness needs no stack; everything between the route and the host edge is the
production code. HTTP clients, including a real browser, therefore see exactly
what a production client sees on the wire.

Run standalone (used by the browser spec)::

    python -m tests.helpers.file_transfer_harness --port 8429

Hosts: system 1 is reached over SSH, system 2 over the agent. ``GET /__state``
returns the recorded audit outcomes and resource counters, and
``POST /__reset`` clears them.
"""

from __future__ import annotations

import argparse
import errno
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List, Optional
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI

from app.api.routes.file_transfer import router
from app.core.auth import get_current_user
from app.db.session import get_db
from app.services import file_transfer_service as fts

from .file_transfer_fakes import (
    RemoteFile,
    TransferEnv,
    content_sha256,
    patched_transfer_env,
    spool_files,
)

SSH_SYSTEM = 1
AGENT_SYSTEM = 2
KIB = 1024
MIB = 1024 * KIB

# Paths served by both hosts. Sizes are chosen to exercise one-chunk, many-chunk
# and unbounded-looking transfers without holding any of them in memory.
SCENARIOS: Dict[str, RemoteFile] = {
    "/ok/small.bin": RemoteFile(size=1234),
    "/ok/medium.bin": RemoteFile(size=5 * MIB + 3),
    "/ok/empty.bin": RemoteFile(size=0),
    "/ok/pseudo.txt": RemoteFile(size=300 * KIB, reports_zero_size=True),
    "/ok/naive \u00fc.bin": RemoteFile(size=2048),
    "/err/denied.bin": RemoteFile(stat_errno=errno.EACCES),
    "/err/dir": RemoteFile(is_dir=True),
    "/err/midstream.bin": RemoteFile(size=8 * MIB, fail_after=3 * MIB),
    "/err/short.bin": RemoteFile(size=4 * MIB, available=MIB),
    "/err/midstream-chunked.bin": RemoteFile(
        size=8 * MIB, fail_after=3 * MIB, reports_zero_size=True
    ),
    "/big/huge.bin": RemoteFile(size=96 * MIB),
    # Too large to finish before a client can cancel (SSH only; over the agent cap).
    "/big/endless.bin": RemoteFile(size=4096 * MIB),
}


class AuditLog:
    """In-memory stand-in for the audit store, recording final outcomes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.rows: Dict[int, Dict[str, Any]] = {}

    def open(self, **kw: Any) -> Any:
        with self._lock:
            row_id = len(self.rows) + 1
            self.rows[row_id] = {
                "id": row_id,
                "path": kw.get("remote_path"),
                "system_id": kw["system"].id,
                "transport": kw.get("transport"),
                "status": "in_progress",
                "error": None,
                "size_bytes": 0,
                "sha256": None,
            }
        return SimpleNamespace(id=row_id, **{k: v for k, v in kw.items()})

    def finish(self, audit_id: int, *, failed, error, size_bytes, sha256) -> None:
        with self._lock:
            self.rows[audit_id].update(
                status="error" if failed else "success",
                error=error,
                size_bytes=size_bytes,
                sha256=None if failed else sha256,
            )

    def finish_row(self, _db: Any, row: Any, **kw: Any) -> None:
        self.finish(
            row.id,
            failed=kw.get("status") == "error",
            error=kw.get("error_message"),
            size_bytes=kw.get("size_bytes", 0),
            sha256=kw.get("sha256"),
        )

    def as_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.rows.values()]


def build_app(env: TransferEnv, audits: AuditLog) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/transfer")
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=1, username="harness", is_admin=True
    )
    app.dependency_overrides[get_db] = lambda: None

    @app.get("/__state")
    def state() -> Dict[str, Any]:
        t = env.tracker
        return {
            "audits": audits.as_list(),
            "leaked": t.leaked,
            "bytes_read": t.bytes_read,
            "spool_files": spool_files(),
            "sha256": {
                p: content_sha256(f.size)
                for p, f in env.files.items()
                if f.size <= 16 * MIB
            },
        }

    @app.post("/__reset")
    def reset() -> Dict[str, bool]:
        audits.rows.clear()
        for name in (
            "sessions_opened",
            "sessions_closed",
            "files_opened",
            "files_closed",
            "broker_streams_opened",
            "broker_streams_closed",
            "bytes_read",
        ):
            setattr(env.tracker, name, 0)
        return {"ok": True}

    return app


@contextmanager
def serving(port: int = 0, host: str = "127.0.0.1") -> Iterator[Dict[str, Any]]:
    """Run the harness in a background thread; yields base URL and handles.

    ``port=0`` picks a free port.
    """
    audits = AuditLog()
    with (
        patched_transfer_env({SSH_SYSTEM: "ssh", AGENT_SYSTEM: "agent"}) as env,
        patch.object(
            fts, "_gate", lambda _db, _u, sid: (SimpleNamespace(id=sid), "ops")
        ),
        patch.object(fts, "_open_audit", lambda _db, **kw: audits.open(**kw)),
        patch.object(fts, "_finish_audit", audits.finish_row),
        patch.object(
            fts,
            "_finalize_download_audit",
            lambda audit_id, *, failed, error, size_bytes, sha256: audits.finish(
                audit_id,
                failed=failed,
                error=error,
                size_bytes=size_bytes,
                sha256=sha256,
            ),
        ),
    ):
        env.files.update(SCENARIOS)
        app = build_app(env, audits)
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        if not server.started:
            raise RuntimeError("harness server did not start")
        bound = server.servers[0].sockets[0].getsockname()[1]
        try:
            yield {
                "base_url": f"http://{host}:{bound}",
                "env": env,
                "audits": audits,
                "server": server,
            }
        finally:
            server.should_exit = True
            thread.join(timeout=10)


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8429)
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104 - test fixture
    args = parser.parse_args(argv)
    with serving(args.port, args.host) as handle:
        print(f"download harness listening on {handle['base_url']}", flush=True)
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
