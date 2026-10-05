from __future__ import annotations
import copy
import time
from dataclasses import dataclass, field
from typing import Any
from .domain import HarnessError

@dataclass(frozen=True)
class EvaluationContext:
    root_session_id: str
    original_task: str = ""
    plan: tuple[str, ...] = ()
    history: tuple[dict[str, Any], ...] = ()
    resources: tuple[dict[str, Any], ...] = ()
    version: int = 0

    @classmethod
    def from_state(cls, root: str, state: dict) -> "EvaluationContext":
        return cls(root,state.get("original_task",""),tuple(state.get("plan",[])),
                   tuple(copy.deepcopy(state.get("history",[]))),tuple(copy.deepcopy(state.get("resources",[]))),state.get("version",0))

def advance_state(state: dict, event, decision) -> dict:
    """Bounded context; full topology remains in the durable journal."""
    from .evidence import redact
    candidate = copy.deepcopy(state)
    if event.event_type == "agent.task.started":
        intent = event.payload.get("intent")
        if not isinstance(intent,str) or not intent.strip(): raise HarnessError("INVALID_TASK","intent must be a nonempty string")
        candidate["original_task"] = redact(intent)[:4096]
        candidate["plan"] = []
    elif event.event_type == "user.prompt.submitted" and not candidate.get("original_task"):
        candidate["original_task"] = redact(str(event.payload.get("prompt","")))[:4096]
    if event.event_type == "agent.plan.updated":
        steps = event.payload.get("steps",[])
        if not isinstance(steps,list) or len(steps)>64 or any(not isinstance(x,str) for x in steps):
            raise HarnessError("INVALID_PLAN","steps must be at most 64 strings")
        candidate["plan"] = [redact(x)[:1024] for x in steps]
    if event.event_type in {"resource.content.received","memory.read","memory.write","tool.call.after"}:
        resource = event.payload.get("resource")
        if resource is not None:
            if not isinstance(resource,dict): raise HarnessError("INVALID_RESOURCE","resource must be an object")
            if not isinstance(resource.get("sensitivity","unknown"),str) or resource.get("sensitivity","unknown") not in {"public","internal","sensitive","unknown"}:
                raise HarnessError("INVALID_RESOURCE","invalid sensitivity label")
            candidate["resources"] = (candidate.get("resources",[]) + [{
                "event_id":event.event_id,"source_ids":[x.source_id for x in event.sources],
                "uri":redact(str(resource.get("uri","")))[:2048],
                "sensitivity":resource.get("sensitivity","unknown"),
            }])[-128:]
    candidate["history"] = (candidate.get("history",[]) + [{
        "event_id":event.event_id,"event_type":event.event_type,"agent_id":event.agent.agent_id,
        "tool_name":str(event.payload.get("tool_name",""))[:256],
        "arguments":redact(event.payload.get("arguments",{})),"decision":str(decision),
        "payload_digest":event.payload_digest,
    }])[-128:]
    candidate["version"] = state.get("version",0)+1
    if len(__import__("json").dumps(candidate).encode()) > 256*1024:
        raise HarnessError("CONTEXT_LIMIT_EXCEEDED","durable context exceeds 256 KiB")
    return candidate

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
