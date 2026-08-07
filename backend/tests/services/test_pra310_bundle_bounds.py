"""PRA-310: uncompressed byte-bound semantics for the diagnostic bundle.

The bundle must enforce per-section and TOTAL UNCOMPRESSED
caps BEFORE compression (not just a final compressed-zip check), truncate oversized
logs with a marker, fail closed on oversized JSON sections, and report uncompressed
byte counts in the manifest.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile

import pytest

from app.core.log_buffer import install_log_buffer
from app.services import diagnostics_service as diag


def _gen(db):
    return diag.generate_bundle(db, actor_user_id=1, time_range="24h")


def _zip(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


# ------------------------------------------------------------------ log truncation


def test_oversized_logs_are_truncated_with_marker(db, monkeypatch):
    monkeypatch.setattr(diag, "MAX_LOG_BYTES", 2048)
    install_log_buffer()
    # Root logger defaults to WARNING outside the app (basicConfig isn't run here),
    # so log at WARNING to ensure records reach the buffer.
    log = logging.getLogger("pra310.bounds")
    for i in range(300):
        log.warning("padding line %04d %s", i, "x" * 80)

    data, manifest = _gen(db)
    logs = _zip(data).read("logs/backend.log")

    # Stays strictly within the (small) cap even after the marker is appended.
    assert len(logs) <= diag.MAX_LOG_BYTES
    assert "log truncated" in logs.decode()
    assert manifest["bounds"]["log_truncated"] is True
    assert manifest["bounds"]["log_omitted_bytes"] > 0


def test_logs_under_cap_are_not_truncated(db):
    install_log_buffer()
    logging.getLogger("pra310.bounds").info("one small line")
    _, manifest = _gen(db)
    assert manifest["bounds"]["log_truncated"] is False
    assert manifest["bounds"]["log_omitted_bytes"] == 0


# ------------------------------------------------------------------ fail-closed caps


def test_total_uncompressed_cap_fails_closed(db, monkeypatch):
    # A tiny total cap must refuse BEFORE compression, not silently ship a small zip.
    monkeypatch.setattr(diag, "MAX_TOTAL_UNCOMPRESSED_BYTES", 50)
    with pytest.raises(diag.DiagnosticsError) as ei:
        _gen(db)
    assert "total uncompressed" in str(ei.value)


def test_oversized_json_section_fails_closed(db, monkeypatch):
    # JSON sections are curated + row-bounded; one over its cap is anomalous -> refuse.
    monkeypatch.setattr(diag, "MAX_JSON_SECTION_BYTES", 10)
    with pytest.raises(diag.DiagnosticsError) as ei:
        _gen(db)
    assert "per-section cap" in str(ei.value)


# ------------------------------------------------------------------ manifest shape


def test_manifest_reports_uncompressed_bytes_and_bounds(db):
    data, manifest = _gen(db)

    assert manifest["total_uncompressed_bytes"] > 0
    bounds = manifest["bounds"]
    assert bounds["max_log_bytes"] == diag.MAX_LOG_BYTES
    assert bounds["max_json_section_bytes"] == diag.MAX_JSON_SECTION_BYTES
    assert bounds["max_total_uncompressed_bytes"] == diag.MAX_TOTAL_UNCOMPRESSED_BYTES
    # Per-file entries carry uncompressed size + digest.
    for f in manifest["files"]:
        assert f["bytes"] >= 0 and f["sha256"]

    # The in-zip manifest (not just the returned dict) carries the bound metadata.
    inzip = json.loads(_zip(data).read("manifest.json"))
    assert "bounds" in inzip
    assert inzip["total_uncompressed_bytes"] == manifest["total_uncompressed_bytes"]


# ------------------------------------------------------------------ member-size guard


def test_no_zip_member_exceeds_its_cap(db):
    data, _ = _gen(db)
    zf = _zip(data)
    for info in zf.infolist():
        if info.filename == "logs/backend.log":
            assert info.file_size <= diag.MAX_LOG_BYTES
        elif info.filename.endswith(".json"):
            assert info.file_size <= diag.MAX_JSON_SECTION_BYTES
    # Total uncompressed of the content sections (manifest excluded) is within cap.
    total = sum(i.file_size for i in zf.infolist() if i.filename != "manifest.json")
    assert total <= diag.MAX_TOTAL_UNCOMPRESSED_BYTES
