from __future__ import annotations
import copy
import uuid
from dataclasses import asdict, dataclass
from typing import Any
from .domain import Decision, HarnessError

@dataclass(frozen=True)
class ToolOutput:
    """Adapters attach observed resource labels and ORIGINAL source ranges."""
    value: Any
    resource: dict | None = None
    sources: tuple = ()
    impacts: tuple = ()

class ToolGateway:
    """SDK enforcement for registered async tools. Adapters own tool-name mapping."""
    def __init__(self,runtime,tools: dict):
        self.runtime = runtime
        self.tools = dict(tools)

    async def call(self,raw: dict,*,confirm=None):
        incoming = copy.deepcopy(raw)
        if incoming.get("event_type") not in {"tool.call.before","subagent.dispatch.before"}:
            raise HarnessError("INVALID_TOOL_EVENT","gateway requires a before event")
        if not isinstance(incoming.get("payload"),dict): raise HarnessError("INVALID_TOOL_EVENT","payload must be an object")
        tool_name = incoming["payload"].get("tool_name")
        if not isinstance(tool_name,str): raise HarnessError("INVALID_TOOL_EVENT","tool_name must be a string")
        if tool_name not in self.tools: raise HarnessError("UNKNOWN_TOOL","tool is not registered")
        event,result = await self.runtime.submit(incoming)
        if result.metadata.get("degraded"):
            raise HarnessError("DETECTOR_UNAVAILABLE","execution suspended because evaluation degraded",status=503)
        if not any(h.status == "SUCCEEDED" for h in result.handler_results):
            raise HarnessError("NO_APPLICABLE_POLICY","no detector evaluated this tool call",status=403)
        if result.decision == Decision.BLOCK:
            raise HarnessError("TOOL_BLOCKED","tool blocked by policy",status=403,details={"audit_id":result.audit_id})
        if result.decision == Decision.REVIEW and confirm is not None:
            # Callback belongs to the trusted UI/host; model output must never approve.
            approved = await confirm(copy.deepcopy(event),copy.deepcopy(result))
            await self.runtime.audit.resolve_approval(result.metadata["approval_id"],approved,"sdk-user")
        await self.runtime.audit.claim_execution(event,result)
        arguments = copy.deepcopy(event.payload.get("arguments",{}))
        try:
            value = await self.tools[tool_name](arguments)
        except BaseException:
            await self.runtime.audit.finish_execution(event.event_id,"TOOL_EXECUTION_FAILED")
            await self._record_outcome(event,"tool.call.error",{"error_code":"TOOL_EXECUTION_FAILED"})
            raise
        await self.runtime.audit.finish_execution(event.event_id)
        output = value if isinstance(value,ToolOutput) else ToolOutput(value)
        await self._record_outcome(event,"tool.call.after",{"result":output.value,"resource":output.resource},
            sources=output.sources,impacts=output.impacts)
        return output.value

    async def _record_outcome(self,event,event_type,payload,*,sources=(),impacts=()):
        raw = event.to_dict()
        raw.pop("received_at")
        raw.pop("seq")
        raw.pop("occurred_at")
        raw.update(event_id=str(uuid.uuid4()),idempotency_key=f"outcome:{event.event_id}",
                   causal_event_id=event.event_id,event_type=event_type,
                   sources=[asdict(x) if hasattr(x,"__dataclass_fields__") else x for x in sources],
                   impacts=[asdict(x) if hasattr(x,"__dataclass_fields__") else x for x in impacts],
                   payload={"tool_name":event.payload["tool_name"],**payload})
        await self.runtime.submit(raw)
