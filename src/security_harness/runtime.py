from __future__ import annotations

import asyncio
import copy
import json
import time
import uuid
from contextlib import asynccontextmanager

from .audit import AuditRepository
from .context import ContextStore, EvaluationContext, advance_state
from .domain import Decision, EventStatus, HandlerResult, HarnessError, RiskSignal, SecurityEvent, SecurityResult
from .pipeline import Pipeline, PipelineOutput


class Runtime:
    def __init__(self, audit: AuditRepository, context: ContextStore | None = None, *, pipeline: Pipeline | None = None,
                 concurrency: int = 32, request_timeout_ms: int = 3000, queue_wait_timeout_ms: int = 500,
                 fail_mode: str = "fail_review"):
        if concurrency < 1 or request_timeout_ms <= 0 or queue_wait_timeout_ms <= 0:
            raise ValueError("concurrency and timeouts must be positive")
        if fail_mode not in {"fail_open", "fail_closed", "fail_review"}: raise ValueError("invalid fail mode")
        self.audit, self.context, self.pipeline = audit, context or ContextStore(), pipeline or Pipeline()
        self.sem = asyncio.Semaphore(concurrency)
        self.request_timeout_ms, self.queue_wait_timeout_ms, self.fail_mode = request_timeout_ms, queue_wait_timeout_ms, fail_mode
        self._lanes: dict[str, list] = {}

    @asynccontextmanager
    async def _lane(self, root: str):
        # All operations on the registry run on the owning event loop without yielding.
        slot = self._lanes.setdefault(root, [asyncio.Lock(), 0])
        slot[1] += 1
        acquired = False
        try:
            await asyncio.wait_for(slot[0].acquire(), self.queue_wait_timeout_ms / 1000)
            acquired = True
            yield
        except asyncio.TimeoutError as exc:
            raise HarnessError("RUNTIME_BUSY", "session lane wait timed out", retryable=True, status=429) from exc
        finally:
            if acquired: slot[0].release()
            slot[1] -= 1
            if slot[1] == 0: self._lanes.pop(root, None)

    async def submit(self, raw: dict, idempotency_header: str | None = None) -> tuple[SecurityEvent, SecurityResult]:
        """Trusted adapters may omit seq; allocation and evaluation share the root lock."""
        if not isinstance(raw, dict): raise HarnessError("INVALID_REQUEST", "body must be an object")
        incoming = copy.deepcopy(raw)
        draft = SecurityEvent.from_dict({**incoming, "seq": incoming.get("seq", 1)}, idempotency_header)
        async with self._lane(draft.root_session_id):
            previous = await self.audit.by_idempotency(draft.idempotency_key)
            if "seq" not in incoming:
                incoming["seq"] = previous["seq"] if previous else await self.audit.last_seq(draft.agent.agent_id, draft.session_id) + 1
            if previous and "occurred_at" not in incoming:
                stored = await self.audit.get(previous["audit_id"])
                if stored["envelope"]: incoming["occurred_at"] = stored["envelope"]["occurred_at"]
            event = SecurityEvent.from_dict(incoming, idempotency_header)
            return event, await self._evaluate(event)

    async def evaluate(self, event: SecurityEvent, request_id: str | None = None) -> SecurityResult:
        # Snapshot mutable dicts supplied by an in-process caller before awaiting.
        event = copy.deepcopy(event)
        async with self._lane(event.root_session_id):
            return await self._evaluate(event, request_id)

    async def _evaluate(self, event: SecurityEvent, request_id: str | None = None) -> SecurityResult:
        request_id = request_id or str(uuid.uuid4())
        started = time.perf_counter()
        try: await asyncio.wait_for(self.sem.acquire(), self.queue_wait_timeout_ms / 1000)
        except asyncio.TimeoutError as exc:
            raise HarnessError("RUNTIME_BUSY", "runtime concurrency limit reached", retryable=True, status=429) from exc
        try:
            previous = await self.audit.by_idempotency(event.idempotency_key)
            if previous:
                mismatch = previous["event_id"] != event.event_id or (
                    previous["fingerprint"] is not None and previous["fingerprint"] != event.fingerprint
                ) or previous["payload_digest"] != event.payload_digest or any((
                    previous["agent_id"] != event.agent.agent_id,previous["session_id"] != event.session_id,
                    previous["seq"] != event.seq,previous["event_type"] != event.event_type,
                ))
                if mismatch: raise HarnessError("IDEMPOTENCY_CONFLICT", "key is bound to different event content", status=409)
                if previous["result_json"] or previous["status"] == EventStatus.COMPLETED:
                    return await self._replay(previous, event)
            expected = await self.audit.last_seq(event.agent.agent_id, event.session_id) + 1
            if event.seq < expected: raise HarnessError("SEQUENCE_TOO_OLD", "seq is older than expected", details={"expected_seq": expected})
            if event.seq > expected: raise HarnessError("SEQUENCE_GAP", "seq has a gap", retryable=True, details={"expected_seq": expected})
            state = await self.audit.load_context(event.root_session_id)
            # Validate prospective state before reserving an audit sequence.
            advance_state(state, event, Decision.REVIEW)
            audit_id = previous["audit_id"] if previous else await self.audit.create_received(event, request_id)
            await self.audit.status(audit_id, EventStatus.PROCESSING)
            try:
                snapshot = EvaluationContext.from_state(event.root_session_id, state)
                out = await asyncio.wait_for(self.pipeline.execute(event, snapshot), self.request_timeout_ms / 1000)
            except asyncio.CancelledError:
                await self.audit.status(audit_id, EventStatus.CANCELLED, error_code="REQUEST_CANCELLED")
                raise
            except Exception as exc:
                code = "REQUEST_TIMEOUT" if isinstance(exc, asyncio.TimeoutError) else "PIPELINE_FAILED"
                out = PipelineOutput(Decision.REVIEW, [RiskSignal(code, "ERROR", "evaluation unavailable")], [], {"degraded": True, "errors": [code]})
            metadata = {**out.metadata, "idempotent_replay": False}
            metadata["context_version"] = state.get("version",0) + 1
            decision = out.decision
            if metadata.get("degraded"):
                fallback = {"fail_open": Decision.ALLOW, "fail_closed": Decision.BLOCK, "fail_review": Decision.REVIEW}[self.fail_mode]
                # A successful detector's REVIEW/BLOCK survives another detector's failure.
                decision = max((fallback,Decision(metadata.get("successful_decision",Decision.ALLOW))),
                               key={Decision.ALLOW:0,Decision.REVIEW:1,Decision.BLOCK:2}.get)
            if event.event_type in {"tool.call.before", "subagent.dispatch.before"} and decision == Decision.REVIEW and not metadata.get("degraded"):
                metadata["approval_id"] = await self.audit.ensure_approval(audit_id, event.fingerprint)
            result = SecurityResult(request_id,event.event_id,decision,out.risk_signals,out.handler_results,
                                    (time.perf_counter()-started)*1000,audit_id,metadata)
            candidate = advance_state(state,event,decision)
            errors = metadata.get("errors", [])
            await self.audit.status(audit_id, EventStatus.FAILED if metadata.get("degraded") else EventStatus.COMPLETED,
                result=result,error_code=errors[0] if errors else None,root_session_id=event.root_session_id,context=candidate)
            return result
        finally: self.sem.release()

    async def _replay(self, row: dict, event: SecurityEvent) -> SecurityResult:
        if row["result_json"]:
            saved = json.loads(row["result_json"])
            result = SecurityResult(saved["request_id"],saved["event_id"],Decision(saved["decision"]),
                [RiskSignal(**x) for x in saved["risk_signals"]],[HandlerResult(**x) for x in saved["handler_results"]],
                saved["elapsed_ms"],saved["audit_id"],{**saved["metadata"],"idempotent_replay":True})
            return result
        # Compatibility with Stage 1/2 databases that predate event_detail.
        audit = await self.audit.get(row["audit_id"])
        handlers = [HandlerResult(h["handler_name"],h["status"],h["duration_ms"],error_code=h["error_code"]) for h in audit["handler_executions"]]
        return SecurityResult(row["request_id"],event.event_id,Decision(row["decision"]),
            [RiskSignal(**x) for x in audit["risk_signals"]],handlers,0,row["audit_id"],
            {"degraded":False,"idempotent_replay":True,"legacy_audit":True})
