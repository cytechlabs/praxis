"""PRA-429: an abandoned file_get body releases the per-op bridge.

The frame pump is the only reader of the bounded ``op.inbound`` queue. When the
HTTP consumer goes away it is cancelled, and without a signal to the bridge an
agent that still has data to send parks the bridge's inbound pump forever. The
stream must cancel a live op and send the outbound end-of-stream sentinel; a
body that was fully consumed must not.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.broker.internal_api import _FileGetStream


def _stream(op_done: bool):
    cancelled = []

    async def cancel(operation_id):
        cancelled.append(operation_id)

    loop = asyncio.get_running_loop()
    completion = loop.create_future()
    if op_done:
        completion.set_result(("success", None))
    op = SimpleNamespace(
        operation_id=7, completion=completion, outbound=asyncio.Queue()
    )
    stream = _FileGetStream(SimpleNamespace(cancel=cancel), op, request=None)
    stream.pump_task = asyncio.create_task(asyncio.sleep(60))
    stream.watch_task = asyncio.create_task(asyncio.sleep(60))
    return stream, op, cancelled


@pytest.mark.asyncio
@pytest.mark.parametrize("op_done", [False, True], ids=["op-live", "op-done"])
async def test_abandoned_body_ends_the_bridge(op_done):
    stream, op, cancelled = _stream(op_done)
    await stream.body_queue.put(b"first")
    body = stream.body_iter()
    assert await body.__anext__() == b"first"
    await body.aclose()  # consumer walks away mid-body
    await asyncio.sleep(0)  # the cancel is fire-and-forget

    assert op.outbound.get_nowait() is None
    assert cancelled == ([] if op_done else [7])
    assert stream.pump_task.cancelled() and stream.watch_task.cancelled()


@pytest.mark.asyncio
async def test_fully_consumed_body_leaves_the_bridge_alone():
    stream, op, cancelled = _stream(op_done=False)
    await stream.body_queue.put(b"all")
    await stream.body_queue.put(None)
    assert [chunk async for chunk in stream.body_iter()] == [b"all"]

    assert op.outbound.empty()
    assert cancelled == []


@pytest.mark.asyncio
async def test_failed_body_releases_the_bridge():
    from app.broker.internal_api import _StreamFailure

    stream, op, _ = _stream(op_done=True)
    await stream.body_queue.put(_StreamFailure("op_stream_closed"))
    with pytest.raises(_StreamFailure):
        async for _ in stream.body_iter():
            pass
    assert op.outbound.get_nowait() is None
