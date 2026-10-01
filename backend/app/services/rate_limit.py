"""In-process sliding-window rate limiting for abuse-prone public endpoints.

State lives in memory, so limits apply per API process and reset on restart.
"""

import time
from collections import deque
from threading import Lock

MAX_TRACKED_KEYS = 10_000


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        """Record an attempt for ``key``; False once the limit for the current window is reached."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) >= MAX_TRACKED_KEYS:
                self._prune(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()

    def _prune(self, now: float) -> None:
        for key in [key for key, hits in self._hits.items() if not hits or now - hits[-1] >= self._window]:
            del self._hits[key]
