from __future__ import annotations
import copy
import time
from dataclasses import dataclass, field
from typing import Any
from .domain import HarnessError

@dataclass
class ContextSnapshot:
    version: int = 0
    values: dict[str, Any] = field(default_factory=dict)
    last_seq: int = 0
    closed_at: float | None = None
    updated_at: float = field(default_factory=time.monotonic)

class ContextStore:
    def __init__(self, ttl_seconds: int = 1800, max_sessions: int = 1000, max_bytes: int = 256 * 1024):
        self.ttl_seconds, self.max_sessions, self.max_bytes = ttl_seconds, max_sessions, max_bytes
        self._items: dict[str, ContextSnapshot] = {}
        self._lock = __import__("asyncio").Lock()

    async def get_snapshot(self, key: str) -> ContextSnapshot:
        async with self._lock:
            self._expire()
            item = self._items.get(key, ContextSnapshot())
            return copy.deepcopy(item)

    async def update(self, key: str, values: dict[str, Any], expected_version: int | None = None, last_seq: int | None = None, close: bool = False) -> ContextSnapshot:
        async with self._lock:
            self._expire()
            current = self._items.get(key, ContextSnapshot())
            if expected_version is not None and expected_version != current.version:
                raise HarnessError("CONTEXT_VERSION_CONFLICT", "context version conflict", retryable=True, details={"expected_version": expected_version, "actual_version": current.version})
            candidate = dict(current.values); candidate.update(values)
            import json
            if len(json.dumps(candidate, ensure_ascii=False).encode()) > self.max_bytes: raise HarnessError("CONTEXT_LIMIT_EXCEEDED", "context exceeds 256 KiB")
            if key not in self._items and len(self._items) >= self.max_sessions: raise HarnessError("CONTEXT_LIMIT_EXCEEDED", "session limit exceeded")
            item = ContextSnapshot(current.version + 1, candidate, last_seq if last_seq is not None else current.last_seq, time.monotonic() if close else current.closed_at, time.monotonic())
            self._items[key] = item
            return copy.deepcopy(item)

    def _expire(self) -> None:
        now = time.monotonic(); self._items = {k: v for k, v in self._items.items() if now - v.updated_at < self.ttl_seconds}

