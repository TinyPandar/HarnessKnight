from __future__ import annotations
import asyncio, json, os, sqlite3, uuid
from typing import Any
from .domain import SecurityEvent, SecurityResult, EventStatus

class AuditRepository:
    def __init__(self, path: str = "data/audit.db"):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL"); self.conn.execute("PRAGMA foreign_keys=ON"); self.conn.execute("PRAGMA busy_timeout=5000")
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
          id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audit_event(audit_id) ON DELETE RESTRICT,
          ordinal INTEGER NOT NULL, handler_name TEXT NOT NULL, status TEXT NOT NULL, duration_ms REAL NOT NULL,
          error_code TEXT, UNIQUE(audit_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS risk_signal (
          id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audit_event(audit_id) ON DELETE RESTRICT,
          code TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL
        );
        """); self.conn.commit(); self._lock = asyncio.Lock()

    async def create_received(self, event: SecurityEvent, request_id: str) -> str:
        audit_id = str(uuid.uuid4())
        async with self._lock:
            try:
                self.conn.execute("INSERT INTO audit_event VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (audit_id, request_id, event.event_id, event.idempotency_key, event.agent.agent_id, event.session_id, event.seq, event.event_type, EventStatus.RECEIVED, None, event.received_at, event.payload_digest, len(json.dumps(event.payload, ensure_ascii=False).encode()), None, None, json.dumps(event.metadata, ensure_ascii=False)))
                self.conn.commit()
            except sqlite3.IntegrityError as exc:
                raise exc
        return audit_id

    async def status(self, audit_id: str, status: EventStatus, *, result: SecurityResult | None = None, error_code: str | None = None, error_message: str | None = None) -> None:
        async with self._lock:
            self.conn.execute("UPDATE audit_event SET status=?, decision=?, error_code=?, error_message=? WHERE audit_id=?", (status, result.decision if result else None, error_code, error_message, audit_id))
            if result:
                for i, h in enumerate(result.handler_results): self.conn.execute("INSERT OR REPLACE INTO handler_execution(audit_id,ordinal,handler_name,status,duration_ms,error_code) VALUES(?,?,?,?,?,?)", (audit_id, i, h.handler_name, h.status, h.duration_ms, h.error_code))
                for r in result.risk_signals: self.conn.execute("INSERT INTO risk_signal(audit_id,code,severity,message) VALUES(?,?,?,?)", (audit_id, r.code, r.severity, r.message))
            self.conn.commit()

    async def get(self, audit_id: str) -> dict[str, Any] | None:
        async with self._lock:
            row = self.conn.execute("SELECT * FROM audit_event WHERE audit_id=?", (audit_id,)).fetchone()
            if not row: return None
            result = dict(row); result["metadata"] = json.loads(result["metadata"])
            result["handler_executions"] = [dict(x) for x in self.conn.execute("SELECT * FROM handler_execution WHERE audit_id=? ORDER BY ordinal", (audit_id,))]
            result["risk_signals"] = [dict(x) for x in self.conn.execute("SELECT code,severity,message FROM risk_signal WHERE audit_id=?", (audit_id,))]
            return result

    async def by_idempotency(self, key: str) -> dict[str, Any] | None:
        async with self._lock:
            row = self.conn.execute("SELECT * FROM audit_event WHERE idempotency_key=?", (key,)).fetchone()
            return dict(row) if row else None

    async def close(self): self.conn.close()

