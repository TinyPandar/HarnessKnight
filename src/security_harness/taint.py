from __future__ import annotations

import os
import time

from .domain import Decision, HandlerResult, RiskSignal


class TaintPropagationHandler:
    name = "taint_propagation"
    rules_version = "taint/1"
    async def execute_with_context(self, event, context):
        started = time.perf_counter()
        if event.event_type not in {"tool.call.before", "subagent.dispatch.before"}:
            return HandlerResult(self.name,"SKIPPED",0,decision=Decision.ALLOW), []
        taint = context.taint
        if not taint.get("tainted"):
            return HandlerResult(self.name,"SUCCEEDED",0,decision=Decision.ALLOW), []
        payload, reasons = event.payload, []
        for impact in event.impacts:
            op = impact.operation.lower()
            if impact.kind == "network": reasons.append("network egress")
            elif impact.kind == "git" and op == "push": reasons.append("git push")
            elif impact.kind == "credential": reasons.append("credential access")
            elif impact.kind == "file" and op in {"write","create","delete","modify","append","move"}:
                cwd = payload.get("cwd"); target = os.path.normpath(impact.target)
                if not isinstance(cwd,str) or not os.path.isabs(cwd): outside = True
                else:
                    try: outside = os.path.commonpath((os.path.normpath(cwd),target)) != os.path.normpath(cwd)
                    except ValueError: outside = True
                if outside: reasons.append(f"write outside cwd: {target}")
        analysis = payload.get("analysis")
        if isinstance(analysis,dict) and analysis.get("unparsed") is True: reasons.append("unparsed tool analysis")
        if payload.get("tool_name") == "Bash" and analysis is None: reasons.append("unanalysed shell")
        if not reasons: return HandlerResult(self.name,"SUCCEEDED",(time.perf_counter()-started)*1000,decision=Decision.ALLOW), []
        sources = taint.get("sources",[])[-16:]
        ids = tuple(x["event_id"] for x in sources if x.get("event_id"))
        source_ids = tuple(s for x in sources for s in x.get("source_ids",[]))
        first = sources[-1] if sources else {}
        message = f"session tainted by {first.get('tool_name','tool')} result {first.get('event_id','unknown')} ({first.get('uri','')}); high-risk action requires approval: {', '.join(reasons)}"
        return HandlerResult(self.name,"SUCCEEDED",(time.perf_counter()-started)*1000,decision=Decision.REVIEW), [RiskSignal("TAINTED_SESSION_HIGH_RISK","WARN",message,source_ids,ids)]
