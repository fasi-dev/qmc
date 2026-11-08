"""In-process abuse limits for the single-instance demo deployment.

* `RateLimiter`  - sliding-window count of new scans per client address.
* `AnalysisGate` - caps concurrent analyses; extra requests get 503 instead of queueing worker threads.

State is in memory, so limits are per process and reset on restart. That is adequate for one instance; a
multi-instance deployment would need a shared store (e.g. Redis) instead.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Callable, Iterator, Mapping

from .ingestion.errors import IngestionError

MAX_TRACKED_CLIENTS = 10_000


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.max_events = max_events
        self.window = window_seconds
        self.clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record one event for `key`. Returns False (and records nothing) if the key is over its limit."""
        if self.max_events <= 0:
            return True                       # 0 or negative disables the limit
        now = self.clock()
        with self._lock:
            q = self._events.get(key)
            if q is None:
                if len(self._events) >= MAX_TRACKED_CLIENTS:
                    self._prune(now)
                    if len(self._events) >= MAX_TRACKED_CLIENTS:   # still full: drop the stalest client
                        self._events.pop(min(self._events, key=lambda k: self._events[k][-1]))
                q = self._events[key] = deque()
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True

    def retry_after(self, key: str) -> int:
        with self._lock:
            q = self._events.get(key)
            if not q:
                return 0
            return max(1, int(q[0] + self.window - self.clock()) + 1)

    def _prune(self, now: float) -> None:
        for k in [k for k, q in self._events.items() if not q or q[-1] <= now - self.window]:
            del self._events[k]


class AnalysisGate:
    def __init__(self, limit: int):
        self.limit = limit
        self._sem = threading.BoundedSemaphore(limit) if limit > 0 else None

    @contextmanager
    def slot(self) -> Iterator[None]:
        if self._sem is None:
            yield
            return
        if not self._sem.acquire(blocking=False):
            raise IngestionError("server_busy", "The server is busy analyzing other repositories. Retry in a minute.", 503)
        try:
            yield
        finally:
            self._sem.release()


def client_key(headers: Mapping[str, str], peer: str | None, trust_proxy: bool) -> str:
    """Client address used for rate limiting. X-Forwarded-For is spoofable, so it is only used when the operator
    says a trusted proxy sets it (QMC_TRUST_PROXY); then the FIRST hop is the original client."""
    if trust_proxy:
        xff = headers.get("x-forwarded-for", "")
        first = xff.split(",")[0].strip()
        if first:
            return first[:64]
    return (peer or "unknown")[:64]


_limiters: dict[tuple[int, int], RateLimiter] = {}
_gates: dict[int, AnalysisGate] = {}
_registry_lock = threading.Lock()


def limiter_for(max_events: int, window_seconds: int) -> RateLimiter:
    with _registry_lock:
        key = (max_events, window_seconds)
        if key not in _limiters:
            _limiters[key] = RateLimiter(max_events, window_seconds)
        return _limiters[key]


def gate_for(limit: int) -> AnalysisGate:
    with _registry_lock:
        if limit not in _gates:
            _gates[limit] = AnalysisGate(limit)
        return _gates[limit]
