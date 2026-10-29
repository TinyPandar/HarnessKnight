from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from urllib.parse import quote

SCHEMA_VERSION = "1.0"
EVENT_TYPES = {
    "agent.session.started", "agent.session.ended", "user.prompt.submitted",
    "agent.task.started", "agent.plan.updated", "resource.content.received",
    "tool.registered", "tool.call.before", "tool.call.after", "tool.call.error",
    "memory.read", "memory.write", "subagent.dispatch.before", "subagent.dispatch.after",
}

class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"

class EventStatus(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    ABANDONED = "ABANDONED"

class HarnessError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False, details: dict[str, Any] | None = None, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.retryable, self.details, self.status = code, message, retryable, details or {}, status

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=_json_default, allow_nan=False).encode())

def _json_default(value: Any) -> str:
    raise TypeError(f"not JSON serializable: {type(value).__name__}")

def validate_metadata(value: dict[str, Any]) -> None:
    try: size = _json_size(value)
    except (TypeError, ValueError) as exc: raise HarnessError("INVALID_METADATA", "metadata must be JSON serializable") from exc
    if size > 32 * 1024:
        raise HarnessError("METADATA_TOO_LARGE", "metadata exceeds 32 KiB")
    def walk(x: Any, depth: int = 1) -> None:
        if depth > 6:
            raise HarnessError("METADATA_DEPTH_EXCEEDED", "metadata nesting exceeds 6 levels")
        if isinstance(x, dict):
            for k, v in x.items():
                if not isinstance(k, str):
                    raise HarnessError("INVALID_METADATA", "metadata keys must be strings")
                walk(v, depth + 1)
        elif isinstance(x, list):
            for v in x: walk(v, depth + 1)
    try: walk(value)
    except TypeError as exc: raise HarnessError("INVALID_METADATA", str(exc)) from exc

@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    agent_type: str = "unknown"
    agent_version: str = "unknown"


@dataclass(frozen=True)
class SourceSpan:
    """Offsets refer to the adapter's ORIGINAL content, before normalization."""
    source_id: str
    kind: str
    uri: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    token_start: int | None = None
    token_end: int | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> "SourceSpan":
        if not isinstance(raw, dict):
            raise HarnessError("INVALID_SOURCE", "source must be an object")
        allowed = set(cls.__dataclass_fields__)
        if set(raw) - allowed or not raw.get("source_id") or not isinstance(raw.get("kind"),str) or raw.get("kind") not in {
            "user", "web", "document", "code", "message", "tool_description",
            "tool_result", "memory", "unknown",
        }:
            raise HarnessError("INVALID_SOURCE", "invalid source id, kind or fields")
        for prefix in ("char", "token"):
            start, end = raw.get(f"{prefix}_start"), raw.get(f"{prefix}_end")
            if (start is None) != (end is None) or (start is not None and (
                type(start) is not int or type(end) is not int or start < 0 or end < start
            )):
                raise HarnessError("INVALID_SOURCE", "offsets must be paired nonnegative ranges")
        if not isinstance(raw["source_id"], str) or len(raw["source_id"])>256 or (raw.get("uri") is not None and (not isinstance(raw["uri"], str) or len(raw["uri"])>8192)):
            raise HarnessError("INVALID_SOURCE", "source id and uri must be strings")
        return cls(**raw)


@dataclass(frozen=True)
class TraceContext:
    root_session_id: str | None = None
    parent_agent_id: str | None = None
    mcp_server_id: str | None = None
    call_id: str | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> "TraceContext":
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise HarnessError("INVALID_TRACE", "invalid trace fields")
        if any(value is not None and (not isinstance(value, str) or not value or len(value)>256) for value in raw.values()):
            raise HarnessError("INVALID_TRACE", "trace values must be nonempty strings")
        return cls(**raw)

@dataclass(frozen=True)
class Impact:
    kind: str
    target: str
    operation: str

    @classmethod
    def from_dict(cls,raw):
        if not isinstance(raw,dict) or set(raw)!={"kind","target","operation"} or not isinstance(raw.get("kind"),str) or raw.get("kind") not in {"file","network","git","credential","agent"}:
            raise HarnessError("INVALID_IMPACT","invalid impact fields or kind")
        if any(not isinstance(raw[k],str) or not raw[k] or len(raw[k])>8192 for k in ("target","operation")):
            raise HarnessError("INVALID_IMPACT","impact target and operation must be nonempty strings")
        return cls(**raw)

@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    idempotency_key: str
    event_type: str
    seq: int
    occurred_at: str
    received_at: str
    agent: AgentIdentity
    session_id: str
    causal_event_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    sources: tuple[SourceSpan, ...] = ()
    trace: TraceContext = field(default_factory=TraceContext)
    impacts: tuple[Impact, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any], idempotency_header: str | None = None) -> "SecurityEvent":
        if not isinstance(raw, dict): raise HarnessError("INVALID_REQUEST", "JSON body must be an object")
        allowed = {"schema_version", "event_id", "idempotency_key", "event_type", "seq", "occurred_at", "agent", "session_id", "causal_event_id", "payload", "metadata", "trace", "sources", "impacts"}
        unknown = set(raw) - allowed
        if unknown: raise HarnessError("INVALID_EVENT", f"unknown fields: {sorted(unknown)}")
        if not isinstance(raw.get("schema_version", SCHEMA_VERSION), str):
            raise HarnessError("INVALID_EVENT", "schema_version must be a string")
        if raw.get("schema_version", SCHEMA_VERSION).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise HarnessError("UNSUPPORTED_SCHEMA_VERSION", "unsupported schema major", details={"schema_version": raw.get("schema_version")})
        key = raw.get("idempotency_key")
        if idempotency_header and key and idempotency_header != key: raise HarnessError("IDEMPOTENCY_KEY_MISMATCH", "header and body idempotency keys differ")
        key = idempotency_header or key
        if not isinstance(key, str) or not 1 <= len(key) <= 128: raise HarnessError("INVALID_EVENT", "idempotency_key is required")
        try:
            event_id = str(uuid.UUID(str(raw["event_id"])))
            seq = raw["seq"]
            if type(seq) is not int or seq < 1: raise ValueError("seq must be a positive integer")
            event_type = raw["event_type"]
            if event_type not in EVENT_TYPES: raise HarnessError("UNSUPPORTED_EVENT_TYPE", f"unsupported event type: {event_type}")
            agent_raw = raw["agent"]
            if not isinstance(agent_raw, dict): raise ValueError("agent must be an object")
            agent = AgentIdentity(agent_raw["agent_id"], agent_raw.get("agent_type", "unknown"), agent_raw.get("agent_version", "unknown"))
            session_id = raw["session_id"]
            if any(not isinstance(x, str) or not x or len(x)>256 for x in (agent.agent_id, agent.agent_type, agent.agent_version, session_id)):
                raise ValueError("agent and session identifiers must be nonempty strings")
        except HarnessError: raise
        except (KeyError, TypeError, ValueError) as exc: raise HarnessError("INVALID_EVENT", f"invalid required field: {exc}") from exc
        payload, metadata = raw.get("payload", {}), raw.get("metadata", {})
        if not isinstance(payload, dict) or not isinstance(metadata, dict): raise HarnessError("INVALID_EVENT", "payload and metadata must be objects")
        validate_metadata(metadata)
        try:
            if _json_size(payload) > 1024 * 1024: raise HarnessError("PAYLOAD_TOO_LARGE", "payload exceeds 1 MiB", status=413)
        except (TypeError, ValueError) as exc: raise HarnessError("INVALID_EVENT", "payload must be JSON serializable") from exc
        stack = [(payload,0)]
        while stack:
            item,depth = stack.pop()
            if depth>32: raise HarnessError("INVALID_EVENT","payload nesting exceeds 32 levels")
            if isinstance(item,dict):
                if any(not isinstance(k,str) for k in item): raise HarnessError("INVALID_EVENT","payload keys must be strings")
                stack.extend((v,depth+1) for v in item.values())
            elif isinstance(item,(list,tuple)): stack.extend((v,depth+1) for v in item)
        source_raw = raw.get("sources", [])
        if not isinstance(source_raw, (list, tuple)) or len(source_raw) > 128:
            raise HarnessError("INVALID_SOURCE", "sources must be a list with at most 128 entries")
        sources = tuple(SourceSpan.from_dict(x) for x in source_raw)
        trace = TraceContext.from_dict(raw.get("trace", {}))
        impact_raw = raw.get("impacts",[])
        if not isinstance(impact_raw,(list,tuple)) or len(impact_raw)>128:
            raise HarnessError("INVALID_IMPACT","impacts must contain at most 128 entries")
        impacts = tuple(Impact.from_dict(x) for x in impact_raw)
        causal = raw.get("causal_event_id")
        if causal is not None:
            try: causal = str(uuid.UUID(causal))
            except (ValueError, TypeError, AttributeError) as exc: raise HarnessError("INVALID_TRACE", "causal_event_id must be a UUID") from exc
        if event_type in {"tool.call.before", "subagent.dispatch.before"}:
            arguments = payload.get("arguments", {})
            if not isinstance(arguments, dict): raise HarnessError("INVALID_EVENT", "tool arguments must be an object")
            if "tool_name" in payload and (not isinstance(payload["tool_name"], str) or not payload["tool_name"]):
                raise HarnessError("INVALID_EVENT", "tool_name must be a nonempty string")
        occurred = str(raw.get("occurred_at", utc_now().isoformat()))
        return cls(event_id, key, event_type, seq, occurred, utc_now().isoformat(), agent, session_id, causal, payload, metadata, str(raw.get("schema_version", SCHEMA_VERSION)), sources, trace, impacts)

    def to_dict(self) -> dict[str, Any]: return asdict(self)
    @property
    def ordering_key(self) -> str: return f"{quote(self.agent.agent_id,safe='')}:{quote(self.session_id,safe='')}"
    @property
    def root_session_id(self) -> str: return self.trace.root_session_id or self.ordering_key
    @property
    def fingerprint(self) -> str:
        """Hash event content while ignoring delivery-specific timestamps and identity."""
        value = self.to_dict()
        for key in ("received_at", "occurred_at", "event_id"):
            value.pop(key)
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    @property
    def payload_digest(self) -> str: return hashlib.sha256(json.dumps(self.payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class RiskSignal:
    code: str
    severity: str = "INFO"
    message: str = ""
    source_ids: tuple[str, ...] = ()
    evidence_event_ids: tuple[str, ...] = ()
    rule_id: str | None = None

@dataclass(frozen=True)
class HandlerResult:
    handler_name: str
    status: str
    duration_ms: float
    decision: Decision | None = None
    error_code: str | None = None

@dataclass(frozen=True)
class SecurityResult:
    request_id: str
    event_id: str
    decision: Decision
    risk_signals: list[RiskSignal]
    handler_results: list[HandlerResult]
    elapsed_ms: float
    audit_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]: return asdict(self)
