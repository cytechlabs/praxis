"""PRA-153 #3e: file-transfer route exception mapping.

Verifies _handle_service_call translates the new transport
exceptions into the right HTTP status codes — without it,
TransportUnavailable / TransportUnsupported would bypass the
FileTransferError handler and surface as 500s, even though the
service had already written the audit row.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.routes.file_transfer import _handle_service_call
from app.services.file_transfer_service import FileTransferError
from app.services.transport import TransportUnavailable, TransportUnsupported


def test_transport_unavailable_maps_to_503():
    """force-agent + tunnel down should be 503 ('this transport
    isn't available right now'), not a generic 500."""

    def _raise():
        raise TransportUnavailable("no tunnel for system 7")

    with pytest.raises(HTTPException) as exc:
        _handle_service_call(_raise)
    assert exc.value.status_code == 503
    assert "no tunnel" in exc.value.detail


def test_transport_unsupported_maps_to_501():
    """force-agent + directory op should be 501 ('not implemented
    by this transport'), surfaced cleanly to the UI."""

    def _raise():
        raise TransportUnsupported("agent doesn't list_dir")

    with pytest.raises(HTTPException) as exc:
        _handle_service_call(_raise)
    assert exc.value.status_code == 501
    assert "list_dir" in exc.value.detail


def test_file_transfer_error_still_handled():
    """Existing FileTransferError handling stays intact."""

    def _raise():
        raise FileTransferError("forbidden: access denied")

    with pytest.raises(HTTPException) as exc:
        _handle_service_call(_raise)
    assert exc.value.status_code == 403


def test_happy_path_passes_through():
    """Non-exception return value is returned unchanged."""

    def _ok():
        return {"ok": True}

    assert _handle_service_call(_ok) == {"ok": True}
