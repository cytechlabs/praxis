"""PRA-339: install_log_buffer is self-healing.

A logging reconfiguration (e.g. logging.basicConfig without force, or a manual
handler swap) can detach the ring-buffer handler from the root logger. Because
the support bundle reads that buffer, a detached handler would silently produce
an empty log section. install_log_buffer must re-attach on the next call.
"""

from __future__ import annotations

import logging

from app.core import log_buffer
from app.core.log_buffer import get_log_buffer, install_log_buffer


def test_reattaches_when_detached_from_root():
    handler = install_log_buffer()
    root = logging.getLogger()
    assert handler in root.handlers

    # Simulate a later logging reconfig that drops our handler.
    root.removeHandler(handler)
    assert handler not in root.handlers

    # Next install must re-attach the SAME handler (not orphan the buffer).
    again = install_log_buffer()
    assert again is handler
    assert handler in root.handlers


def test_records_flow_after_reattach():
    install_log_buffer()
    buf = get_log_buffer()
    root = logging.getLogger()
    root.removeHandler(buf)  # detach

    install_log_buffer()  # self-heal
    logging.getLogger("pra339.reattach").warning("pra339-reattach-marker")

    assert any(
        "pra339-reattach-marker" in r["message"] for r in buf.records(limit=5000)
    )


def test_no_duplicate_handler_on_repeated_install():
    install_log_buffer()
    install_log_buffer()
    install_log_buffer()
    root = logging.getLogger()
    ring = [h for h in root.handlers if isinstance(h, log_buffer.RingBufferLogHandler)]
    assert len(ring) == 1
