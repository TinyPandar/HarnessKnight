from __future__ import annotations
import asyncio, time, uuid
from .audit import AuditRepository
from .context import ContextStore
from .domain import Decision, EventStatus, HarnessError, SecurityEvent, SecurityResult
from .pipeline import Pipeline

class Runtime:
    def __init__(self, audit: AuditRepository, context: ContextStore | None = None, *, pipeline: Pipeline | None = None, concurrency: int = 32, request_timeout_ms: int = 3000, queue_wait_timeout_ms: int = 500, fail_mode: str = "fail_review"):
        self.audit, self.context, self.pipeline = audit, context or ContextStore(), pipeline or Pipeline()
        self.sem = asyncio.Semaphore(concurrency); self.request_timeout_ms, self.queue_wait_timeout_ms, self.fail_mode = request_timeout_ms, queue_wait_timeout_ms, fail_mode
        self.locks: dict[str, asyncio.Lock] = {}; self.seq: dict[str, int] = {}; self.key_lock = asyncio.Lock()

    async def _lane(self, key: str) -> asyncio.Lock:
        async with self.key_lock: return self.locks.setdefault(key, asyncio.Lock())

    async def evaluate(self, event: SecurityEvent, request_id: str | None = None) -> SecurityResult:
        request_id = request_id or str(uuid.uuid4()); started = time.perf_counter(); lane = await self._lane(event.ordering_key)
        try:
            await asyncio.wait_for(self.sem.acquire(), self.queue_wait_timeout_ms / 1000)
        except asyncio.TimeoutError as exc: raise HarnessError("RUNTIME_BUSY", "runtime concurrency limit reached", retryable=True, status=429) from exc
        try:
            async with lane:
                expected = self.seq.get(event.ordering_key, 0) + 1
                previous = await self.audit.by_idempotency(event.idempotency_key)
                if previous:
                    if previous["event_id"] != event.event_id: raise HarnessError("IDEMPOTENCY_CONFLICT", "idempotency key maps to another event", status=409)
                    if previous["status"] == EventStatus.COMPLETED:
                        return await self._replay(previous, event)
                if event.seq < expected: raise HarnessError("SEQUENCE_TOO_OLD", "received seq is older than expected", details={"expected_seq": expected, "received_seq": event.seq})
                if event.seq > expected: raise HarnessError("SEQUENCE_GAP", f"Expected seq {expected} but received {event.seq}", retryable=True, details={"expected_seq": expected, "received_seq": event.seq})
                audit_id = await self.audit.create_received(event, request_id)
                await self.audit.status(audit_id, EventStatus.QUEUED); await self.audit.status(audit_id, EventStatus.PROCESSING)
                try:
                    out = await asyncio.wait_for(self.pipeline.execute(event), self.request_timeout_ms / 1000)
                    result = SecurityResult(request_id, event.event_id, out.decision, out.risk_signals, out.handler_results, (time.perf_counter()-started)*1000, audit_id, {"degraded": False, "idempotent_replay": False})
                    await self.audit.status(audit_id, EventStatus.COMPLETED, result=result); self.seq[event.ordering_key] = event.seq
                    await self.context.update(event.ordering_key, {"last_event_type": event.event_type}, last_seq=event.seq, close=event.event_type == "agent.session.ended")
                    return result
                except asyncio.CancelledError:
                    await self.audit.status(audit_id, EventStatus.CANCELLED, error_code="REQUEST_CANCELLED", error_message="request cancelled"); raise
                except asyncio.TimeoutError:
                    await self.audit.status(audit_id, EventStatus.TIMED_OUT, error_code="REQUEST_TIMEOUT", error_message="request timed out")
                    raise HarnessError("REQUEST_TIMEOUT", "request timed out", retryable=True, status=504)
                except HarnessError as exc:
                    await self.audit.status(audit_id, EventStatus.FAILED, error_code=exc.code, error_message=exc.message)
                    return await self._degraded(event, request_id, audit_id, started, exc)
        finally: self.sem.release()

    async def _replay(self, row: dict, event: SecurityEvent) -> SecurityResult:
        audit = await self.audit.get(row["audit_id"]); handlers = []
        for h in audit.get("handler_executions", []):
            from .domain import HandlerResult
            handlers.append(HandlerResult(h["handler_name"], h["status"], h["duration_ms"], error_code=h["error_code"]))
        from .domain import RiskSignal
        signals = [RiskSignal(x["code"], x["severity"], x["message"]) for x in audit.get("risk_signals", [])]
        return SecurityResult(row["request_id"], event.event_id, Decision(row["decision"]), signals, handlers, 0, row["audit_id"], {"degraded": False, "idempotent_replay": True})

    async def _degraded(self, event, request_id, audit_id, started, exc):
        decision = {"fail_open": Decision.ALLOW, "fail_closed": Decision.BLOCK, "fail_review": Decision.REVIEW}.get(self.fail_mode, Decision.REVIEW)
        from .domain import HandlerResult, RiskSignal
        result = SecurityResult(request_id, event.event_id, decision, [RiskSignal(exc.code, "ERROR", exc.message)], [HandlerResult(self.pipeline.handler_name, "FAILED", 0, error_code=exc.code)], (time.perf_counter()-started)*1000, audit_id, {"degraded": True, "error_code": exc.code, "idempotent_replay": False})
        await self.audit.status(audit_id, EventStatus.FAILED, result=result, error_code=exc.code, error_message=exc.message)
        return result
