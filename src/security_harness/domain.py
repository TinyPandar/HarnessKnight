from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0"
EVENT_TYPES = {"agent.session.started", "user.prompt.submitted", "tool.call.before", "tool.call.after", "tool.call.error", "agent.session.ended"}

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
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=_json_default).encode())

def _json_default(value: Any) -> str:
    raise TypeError(f"not JSON serializable: {type(value).__name__}")

def validate_metadata(value: dict[str, Any]) -> None:
    if _json_size(value) > 32 * 1024:
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

    @classmethod
    def from_dict(cls, raw: dict[str, Any], idempotency_header: str | None = None) -> "SecurityEvent":
        if not isinstance(raw, dict): raise HarnessError("INVALID_REQUEST", "JSON body must be an object")
        allowed = {"schema_version", "event_id", "idempotency_key", "event_type", "seq", "occurred_at", "agent", "session_id", "causal_event_id", "payload", "metadata", "trace"}
        unknown = set(raw) - allowed
        if unknown: raise HarnessError("INVALID_EVENT", f"unknown fields: {sorted(unknown)}")
        if raw.get("schema_version", SCHEMA_VERSION).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise HarnessError("UNSUPPORTED_SCHEMA_VERSION", "unsupported schema major", details={"schema_version": raw.get("schema_version")})
        key = raw.get("idempotency_key")
        if idempotency_header and key and idempotency_header != key: raise HarnessError("IDEMPOTENCY_KEY_MISMATCH", "header and body idempotency keys differ")
        key = idempotency_header or key
        if not isinstance(key, str) or not 1 <= len(key) <= 128: raise HarnessError("INVALID_EVENT", "idempotency_key is required")
        try:
            event_id = str(uuid.UUID(str(raw["event_id"])))
            seq = int(raw["seq"])
            if seq < 1: raise ValueError
            event_type = raw["event_type"]
            if event_type not in EVENT_TYPES: raise HarnessError("UNSUPPORTED_EVENT_TYPE", f"unsupported event type: {event_type}")
            agent_raw = raw["agent"]
            agent = AgentIdentity(str(agent_raw["agent_id"]), str(agent_raw.get("agent_type", "unknown")), str(agent_raw.get("agent_version", "unknown")))
            session_id = str(raw["session_id"])
        except HarnessError: raise
        except (KeyError, TypeError, ValueError) as exc: raise HarnessError("INVALID_EVENT", f"invalid required field: {exc}") from exc
        payload, metadata = raw.get("payload", {}), raw.get("metadata", {})
        if not isinstance(payload, dict) or not isinstance(metadata, dict): raise HarnessError("INVALID_EVENT", "payload and metadata must be objects")
        validate_metadata(metadata)
        occurred = str(raw.get("occurred_at", utc_now().isoformat()))
        return cls(event_id, key, event_type, seq, occurred, utc_now().isoformat(), agent, session_id, raw.get("causal_event_id"), payload, metadata, str(raw.get("schema_version", SCHEMA_VERSION)))

    def to_dict(self) -> dict[str, Any]: return asdict(self)
    @property
    def ordering_key(self) -> str: return f"{self.agent.agent_id}:{self.session_id}"
    @property
    def payload_digest(self) -> str: return hashlib.sha256(json.dumps(self.payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class RiskSignal:
    code: str
    severity: str = "INFO"
    message: str = ""

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

