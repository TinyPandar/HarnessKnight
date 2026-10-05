from __future__ import annotations
import asyncio
import copy
import time
from dataclasses import dataclass, field
from typing import Protocol
from .context import EvaluationContext
from .domain import Decision, HandlerResult, RiskSignal, SecurityEvent

@dataclass
class PipelineOutput:
    decision: Decision
    risk_signals: list[RiskSignal]
    handler_results: list[HandlerResult]
    metadata: dict = field(default_factory=dict)

class HandlerProtocol(Protocol):
    name: str
    async def execute(self, event: SecurityEvent) -> tuple[HandlerResult, list[RiskSignal]]: ...

class ContextHandlerProtocol(Protocol):
    name: str
    async def execute_with_context(self, event: SecurityEvent, context: EvaluationContext) -> tuple[HandlerResult, list[RiskSignal]]: ...

class ObservationHandler:
    """Explicit observation mode; it makes no security claim."""
    name = "observation"
    async def execute(self, event):
        return HandlerResult(self.name, "SKIPPED", 0, decision=Decision.ALLOW), []

class MockRuleHandler:
    name = "mock_rule"
    async def execute(self, event):
        started = time.perf_counter()
        meta = event.metadata.get("test.mock", {})
        if isinstance(meta, dict):
            if meta.get("delay_ms"): await asyncio.sleep(float(meta["delay_ms"]) / 1000)
            if meta.get("raise"): raise ValueError(str(meta["raise"]))
            action = str(meta.get("action", "allow")).lower()
        else: action = "allow"
        decision = {"allow": Decision.ALLOW, "block": Decision.BLOCK, "review": Decision.REVIEW}.get(action, Decision.ALLOW)
        return HandlerResult(self.name,"SUCCEEDED",(time.perf_counter()-started)*1000,decision=decision), []

class Pipeline:
    def __init__(self, handler: HandlerProtocol | None = None, handler_timeout_ms: int = 1000, *, handlers=None):
        if handler is not None and handlers is not None: raise ValueError("use handler or handlers, not both")
        self.handlers = tuple(handlers) if handlers is not None else (handler if handler is not None else ObservationHandler(),)
        if not self.handlers or len({h.name for h in self.handlers}) != len(self.handlers):
            raise ValueError("pipeline requires uniquely named handlers")
        if handler_timeout_ms <= 0: raise ValueError("timeout must be positive")
        self.handler_timeout_ms = handler_timeout_ms
    @property
    def handler(self): return self.handlers[0]
    @property
    def handler_name(self): return ",".join(h.name for h in self.handlers)
    async def execute(self, event: SecurityEvent, context: EvaluationContext | None = None) -> PipelineOutput:
        results, signals, failures = [], [], []
        rank = {Decision.ALLOW:0, Decision.REVIEW:1, Decision.BLOCK:2}
        decision = Decision.ALLOW
        successful_decision = Decision.ALLOW
        for handler in self.handlers:
            started = time.perf_counter()
            try:
                isolated_event = copy.deepcopy(event)
                work = handler.execute_with_context(isolated_event, copy.deepcopy(context)) if hasattr(handler,"execute_with_context") else handler.execute(isolated_event)
                result, emitted = await asyncio.wait_for(work,self.handler_timeout_ms/1000)
                current = Decision(result.decision) if result.decision is not None else Decision.REVIEW
                if result.status not in {"SUCCEEDED","SKIPPED"}: raise ValueError("invalid handler status")
                results.append(result)
                signals.extend(emitted)
                if rank[current] > rank[successful_decision]: successful_decision = current
            except asyncio.CancelledError: raise
            except Exception as exc:
                timeout = isinstance(exc,asyncio.TimeoutError)
                code = "HANDLER_TIMEOUT" if timeout else "HANDLER_FAILED"
                failures.append(code)
                results.append(HandlerResult(handler.name,"TIMED_OUT" if timeout else "FAILED",(time.perf_counter()-started)*1000,error_code=code))
                signals.append(RiskSignal(code,"ERROR",f"{handler.name}: detector unavailable"))
                current = Decision.REVIEW
            if rank[current] > rank[decision]: decision = current
        versions = {h.name:{key:getattr(h,key) for key in ("dataset_sha256","rules_version","policy_version") if hasattr(h,key)} for h in self.handlers}
        return PipelineOutput(decision,signals,results,{"degraded":bool(failures),"detector_versions":versions,"errors":failures,"successful_decision":successful_decision})
