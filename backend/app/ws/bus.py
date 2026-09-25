"""In-process event bus feeding the WebSocket SOC stream.

Thread-safe by design: sync pipeline code calls publish_sync() from worker
threads; the async WS handler drains the queue. No Redis/Kafka in Phase 11 —
the interface (publish/subscribe) is ready to swap the transport later.
"""
import queue
from datetime import datetime, timezone
from typing import Any

MAX_QUEUE = 10000

_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE)


def publish_sync(event_type: str, payload: dict[str, Any] | None = None) -> None:
    try:
        _queue.put_nowait({"type": event_type,
                           "ts": datetime.now(timezone.utc).isoformat(),
                           "payload": payload or {}})
    except queue.Full:
        pass


def drain(limit: int = 100) -> list[dict]:
    out = []
    while len(out) < limit:
        try:
            out.append(_queue.get_nowait())
        except queue.Empty:
            break
    return out


def clear() -> None:
    drain(limit=MAX_QUEUE)
