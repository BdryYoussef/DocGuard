"""Bounded process-local controls for the qualified single-worker deployment."""

from __future__ import annotations

import threading
import time
from collections import deque

_MAX_BUCKETS = 20_000


class AbuseRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def consume(self, *, action: str, actor_id: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        key = f"{action}:{actor_id}"
        cutoff = now - window_seconds
        with self._lock:
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= _MAX_BUCKETS:
                    return False
                events = self._events[key] = deque()
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True


__all__ = ["AbuseRateLimiter"]
