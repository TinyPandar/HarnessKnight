from __future__ import annotations

from uuid import uuid4

from .agentguard.detection_v2 import (
    DETECTOR_VERSION,
    ScanLimitExceeded,
    detect_indirect,
)
from .domain import Decision, HandlerResult, HarnessError, RiskSignal, SecurityEvent


class IndirectInjectionHandler:
    """Run bounded AgentGuard-derived advisory detection on event text."""

    name = "indirect_injection"
    rules_version = DETECTOR_VERSION

    def __init__(self, *, direct_decision: Decision = Decision.REVIEW,
                 indirect_decision: Decision = Decision.REVIEW):
        self.direct_decision = Decision(direct_decision)
        self.indirect_decision = Decision(indirect_decision)

    async def execute(self, event: SecurityEvent):
        if event.event_type == "user.prompt.submitted":
            text = event.payload.get("prompt")
            source = "DIRECT"
            if not isinstance(text, str):
                raise HarnessError("INVALID_PROMPT", "payload.prompt must be a string")
        elif event.event_type in {"resource.content.received", "tool.call.after"}:
            field = next((k for k in ("content", "text", "output", "result") if k in event.payload), None)
            if field is None:
                return HandlerResult(self.name, "SKIPPED", 0, decision=Decision.ALLOW), []
            text = event.payload[field]
            source = "INDIRECT"
            if not isinstance(text, str):
                raise HarnessError("INVALID_CONTENT", "event content must be a string")
        else:
            return HandlerResult(self.name, "SKIPPED", 0, decision=Decision.ALLOW), []
        try:
            _, finding = detect_indirect(text, artifact_id=event.event_id,
                                         finding_id=uuid4().hex, attack_source=source)
        except ScanLimitExceeded:
            return HandlerResult(self.name, "SUCCEEDED", 0, decision=Decision.REVIEW), [
                RiskSignal("CONTENT_SCAN_LIMIT_EXCEEDED", "WARN", "内容超过扫描长度上限", rule_id="CONTENT_SCAN_LIMIT_EXCEEDED")]
        if finding is None:
            return HandlerResult(self.name, "SUCCEEDED", 0, decision=Decision.ALLOW), []
        data = finding.to_dict()
        family = data["attack_family"]
        reason = data["reasons"][0]
        decision = self.direct_decision if source == "DIRECT" else self.indirect_decision
        signal = RiskSignal(f"INDIRECT_INJECTION:{family}", "WARN", reason, rule_id=reason)
        return HandlerResult(self.name, "SUCCEEDED", 0, decision=decision), [signal]
