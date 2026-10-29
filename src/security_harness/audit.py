from __future__ import annotations
import asyncio
import json
import os
import sqlite3
import time
import uuid
from typing import Any
from .domain import EventStatus, HarnessError, SecurityEvent, SecurityResult
from .evidence import redact

class AuditRepository:
    """Single-process journal. Final result and context commit atomically."""
    def __init__(self, path: str = "data/audit.db"):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS audit_event (
          audit_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE,
          idempotency_key TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL, session_id TEXT NOT NULL,
          seq INTEGER NOT NULL, event_type TEXT NOT NULL, status TEXT NOT NULL, decision TEXT,
          received_at TEXT NOT NULL, payload_digest TEXT NOT NULL, payload_size INTEGER NOT NULL,
          error_code TEXT, error_message TEXT, metadata TEXT NOT NULL DEFAULT '{}'
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_session_seq ON audit_event(agent_id, session_id, seq);
        CREATE TABLE IF NOT EXISTS handler_execution (
          id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audit_event(audit_id),
          ordinal INTEGER NOT NULL, handler_name TEXT NOT NULL, status TEXT NOT NULL,
          duration_ms REAL NOT NULL, error_code TEXT, UNIQUE(audit_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS risk_signal (
          id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audit_event(audit_id),
          code TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_detail (
          audit_id TEXT PRIMARY KEY REFERENCES audit_event(audit_id), root_session_id TEXT NOT NULL,
          fingerprint TEXT NOT NULL, envelope TEXT NOT NULL, result_json TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_event_root ON event_detail(root_session_id);
        CREATE TABLE IF NOT EXISTS session_state (root_session_id TEXT PRIMARY KEY, state_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS approval (
          approval_id TEXT PRIMARY KEY, audit_id TEXT NOT NULL UNIQUE REFERENCES audit_event(audit_id),
          fingerprint TEXT NOT NULL, expires_at REAL NOT NULL, state TEXT NOT NULL,
          actor TEXT, resolved_at REAL
        );
        CREATE TABLE IF NOT EXISTS tool_execution (
          event_id TEXT PRIMARY KEY REFERENCES audit_event(event_id), state TEXT NOT NULL,
          started_at REAL NOT NULL, ended_at REAL, error_code TEXT
        );
        """)
        self.conn.commit()
        self._lock = asyncio.Lock()

    async def create_received(self, event: SecurityEvent, request_id: str) -> str:
        audit_id = str(uuid.uuid4())
        envelope = event.to_dict()
        envelope["payload"] = {"digest": event.payload_digest, "keys": sorted(event.payload)}
        envelope["metadata"] = {}
        envelope = redact(envelope)
        async with self._lock:
            if event.causal_event_id:
                parent = self.conn.execute("""SELECT COALESCE(d.root_session_id,e.agent_id || ':' || e.session_id) root
                    FROM audit_event e LEFT JOIN event_detail d USING(audit_id) WHERE e.event_id=?""",
                    (event.causal_event_id,)).fetchone()
                if not parent or parent["root"] != event.root_session_id:
                    raise HarnessError("INVALID_CAUSAL_PARENT", "parent must already exist in the same root session")
            try:
                with self.conn:
                    self.conn.execute("INSERT INTO audit_event VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                        audit_id, request_id, event.event_id, event.idempotency_key, event.agent.agent_id,
                        event.session_id, event.seq, event.event_type, EventStatus.RECEIVED, None,
                        event.received_at, event.payload_digest, len(json.dumps(event.payload).encode()), None, None, "{}"))
                    self.conn.execute("INSERT INTO event_detail VALUES (?,?,?,?,NULL)", (
                        audit_id, event.root_session_id, event.fingerprint, json.dumps(envelope)))
            except sqlite3.IntegrityError as exc:
                raise HarnessError("EVENT_CONFLICT", "event id, idempotency key or sequence already exists", status=409) from exc
        return audit_id

    async def status(self, audit_id: str, status: EventStatus, *, result: SecurityResult | None = None,
                     error_code: str | None = None, error_message: str | None = None,
                     root_session_id: str | None = None, context: dict | None = None) -> None:
        async with self._lock:
            with self.conn:
                self.conn.execute("UPDATE audit_event SET status=?,decision=?,error_code=?,error_message=? WHERE audit_id=?",
                    (status, result.decision if result else None, error_code, error_message, audit_id))
                if result:
                    self.conn.execute("UPDATE event_detail SET result_json=? WHERE audit_id=?", (json.dumps(result.to_dict()), audit_id))
                    self.conn.execute("DELETE FROM handler_execution WHERE audit_id=?", (audit_id,))
                    self.conn.execute("DELETE FROM risk_signal WHERE audit_id=?", (audit_id,))
                    for i, h in enumerate(result.handler_results):
                        self.conn.execute("INSERT INTO handler_execution(audit_id,ordinal,handler_name,status,duration_ms,error_code) VALUES(?,?,?,?,?,?)",
                            (audit_id,i,h.handler_name,h.status,h.duration_ms,h.error_code))
                    for r in result.risk_signals:
                        self.conn.execute("INSERT INTO risk_signal(audit_id,code,severity,message) VALUES(?,?,?,?)",
                            (audit_id,r.code,r.severity,r.message))
                if context is not None and root_session_id is not None:
                    self.conn.execute("INSERT INTO session_state VALUES (?,?) ON CONFLICT(root_session_id) DO UPDATE SET state_json=excluded.state_json",
                        (root_session_id,json.dumps(context)))

    async def get(self, audit_id: str) -> dict[str, Any] | None:
        async with self._lock:
            row = self.conn.execute("SELECT e.*,d.root_session_id,d.fingerprint,d.envelope,d.result_json FROM audit_event e LEFT JOIN event_detail d USING(audit_id) WHERE audit_id=?", (audit_id,)).fetchone()
            if not row: return None
            result = dict(row)
            result["metadata"] = json.loads(result["metadata"])
            for key in ("envelope", "result_json"):
                result[key] = json.loads(result[key]) if result[key] else None
            result["handler_executions"] = [dict(x) for x in self.conn.execute("SELECT * FROM handler_execution WHERE audit_id=? ORDER BY ordinal", (audit_id,))]
            result["risk_signals"] = [dict(x) for x in self.conn.execute("SELECT code,severity,message FROM risk_signal WHERE audit_id=?", (audit_id,))]
            return result

    async def by_idempotency(self, key: str) -> dict[str, Any] | None:
        async with self._lock:
            row = self.conn.execute("SELECT e.*,d.fingerprint,d.result_json FROM audit_event e LEFT JOIN event_detail d USING(audit_id) WHERE idempotency_key=?", (key,)).fetchone()
            return dict(row) if row else None

    async def last_seq(self, agent_id: str, session_id: str) -> int:
        async with self._lock:
            row = self.conn.execute("""SELECT COALESCE(MAX(seq),0) FROM audit_event e LEFT JOIN event_detail d USING(audit_id)
                WHERE agent_id=? AND session_id=? AND (d.result_json IS NOT NULL OR e.status='COMPLETED')""", (agent_id,session_id)).fetchone()
            return row[0]

    async def load_context(self, root: str) -> dict:
        async with self._lock:
            row = self.conn.execute("SELECT state_json FROM session_state WHERE root_session_id=?", (root,)).fetchone()
            return json.loads(row[0]) if row else {}

    async def trace(self, root: str) -> list[dict]:
        async with self._lock:
            rows = self.conn.execute("""SELECT e.*,d.envelope,d.result_json FROM audit_event e
                JOIN event_detail d USING(audit_id) WHERE root_session_id=? ORDER BY e.rowid""", (root,))
            return [{**dict(row), "envelope": json.loads(row["envelope"]),
                     "result_json": json.loads(row["result_json"]) if row["result_json"] else None} for row in rows]

    async def ensure_approval(self, audit_id: str, fingerprint: str, ttl: int = 300) -> str:
        async with self._lock:
            row = self.conn.execute("SELECT approval_id FROM approval WHERE audit_id=?", (audit_id,)).fetchone()
            if row: return row[0]
            approval_id = str(uuid.uuid4())
            with self.conn:
                self.conn.execute("INSERT INTO approval VALUES (?,?,?,?,?,NULL,NULL)", (approval_id,audit_id,fingerprint,time.time()+ttl,"PENDING"))
            return approval_id

    async def resolve_approval(self, approval_id: str, approved: bool, actor: str) -> None:
        if type(approved) is not bool or not isinstance(actor, str) or not actor.strip():
            raise HarnessError("INVALID_APPROVAL", "approved must be boolean and actor nonempty")
        async with self._lock:
            with self.conn:
                cursor = self.conn.execute("UPDATE approval SET state=?,actor=?,resolved_at=? WHERE approval_id=? AND state='PENDING' AND expires_at>?",
                    ("APPROVED" if approved else "DENIED",actor,time.time(),approval_id,time.time()))
                if cursor.rowcount != 1:
                    raise HarnessError("APPROVAL_UNAVAILABLE", "approval missing, expired or already resolved", status=409)

    async def claim_execution(self, event: SecurityEvent, result: SecurityResult) -> None:
        async with self._lock:
            with self.conn:
                record = self.conn.execute("SELECT fingerprint,result_json,root_session_id FROM event_detail WHERE audit_id=?", (result.audit_id,)).fetchone()
                if not record or record["fingerprint"] != event.fingerprint or not record["result_json"]:
                    raise HarnessError("CALL_BINDING_MISMATCH","execution must match the evaluated event",status=403)
                original = self.conn.execute("SELECT event_id FROM audit_event WHERE audit_id=?", (result.audit_id,)).fetchone()
                if not original or original["event_id"] != event.event_id:
                    raise HarnessError("CALL_BINDING_MISMATCH","execution event id must match the evaluated event",status=403)
                saved = json.loads(record["result_json"])
                if saved["decision"] != result.decision or saved["metadata"].get("degraded"):
                    raise HarnessError("CALL_BINDING_MISMATCH","execution result cannot be modified",status=403)
                if result.decision == "BLOCK": raise HarnessError("TOOL_BLOCKED","tool blocked by policy",status=403)
                state = self.conn.execute("SELECT state_json FROM session_state WHERE root_session_id=?", (record["root_session_id"],)).fetchone()
                if not state or json.loads(state[0]).get("version") != saved["metadata"].get("context_version"):
                    raise HarnessError("CONTEXT_CHANGED","context changed; submit a fresh call for evaluation",status=409)
                if result.decision == "REVIEW":
                    cursor = self.conn.execute("UPDATE approval SET state='CONSUMED' WHERE approval_id=? AND audit_id=? AND fingerprint=? AND state='APPROVED' AND expires_at>?",
                        (result.metadata.get("approval_id"),result.audit_id,event.fingerprint,time.time()))
                    if cursor.rowcount != 1:
                        raise HarnessError("APPROVAL_REQUIRED", "tool requires a valid call-bound approval", status=403)
                try:
                    self.conn.execute("INSERT INTO tool_execution VALUES (?,?,?,NULL,NULL)", (event.event_id,"STARTED",time.time()))
                except sqlite3.IntegrityError as exc:
                    raise HarnessError("EXECUTION_ALREADY_CLAIMED", "tool execution cannot be repeated", status=409) from exc

    async def finish_execution(self, event_id: str, error_code: str | None = None) -> None:
        async with self._lock:
            with self.conn:
                self.conn.execute("UPDATE tool_execution SET state=?,ended_at=?,error_code=? WHERE event_id=?",
                    ("FAILED" if error_code else "COMPLETED",time.time(),error_code,event_id))

    async def close(self): self.conn.close()
