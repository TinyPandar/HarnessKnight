from __future__ import annotations
import asyncio, time
from dataclasses import dataclass
from .domain import Decision, HandlerResult, HarnessError, RiskSignal, SecurityEvent

@dataclass
class PipelineOutput:
    decision: Decision
    risk_signals: list[RiskSignal]
    handler_results: list[HandlerResult]

class MockRuleHandler:
    name = "mock_rule"
    async def execute(self, event: SecurityEvent) -> HandlerResult:
        started = time.perf_counter(); meta = event.metadata.get("test.mock", {})
        # Explicit test-only namespace. This is not a security rule.
        if isinstance(meta, dict):
            delay = meta.get("delay_ms", 0)
            if delay: await asyncio.sleep(float(delay) / 1000)
            if meta.get("raise"): raise ValueError(str(meta["raise"]))
            action = str(meta.get("action", "allow")).lower()
        else: action = "allow"
        decision = {"allow": Decision.ALLOW, "block": Decision.BLOCK, "review": Decision.REVIEW}.get(action, Decision.ALLOW)
        return HandlerResult(self.name, "SUCCEEDED", (time.perf_counter() - started) * 1000, decision=decision)

class Pipeline:
    def __init__(self, handler_timeout_ms: int = 1000): self.handler_timeout_ms = handler_timeout_ms; self.handler = MockRuleHandler()
    async def execute(self, event: SecurityEvent) -> PipelineOutput:
        try:
            result = await asyncio.wait_for(self.handler.execute(event), self.handler_timeout_ms / 1000)
            return PipelineOutput(result.decision or Decision.REVIEW, [], [result])
        except asyncio.TimeoutError as exc:
            r = HandlerResult(self.handler.name, "TIMED_OUT", float(self.handler_timeout_ms), error_code="HANDLER_TIMEOUT")
            raise HarnessError("HANDLER_TIMEOUT", "handler timed out", retryable=True, status=504) from exc
        except asyncio.CancelledError: raise
        except Exception as exc:
            raise HarnessError("HANDLER_FAILED", str(exc), retryable=False, status=500) from exc

