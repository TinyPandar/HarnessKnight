"""Small, validated JSON policy DSL. No Python expressions or eval."""
from __future__ import annotations
import fnmatch
import json
import time
from dataclasses import asdict
from pathlib import Path
from .domain import Decision, HandlerResult, RiskSignal

_MISSING = object()
_OPS = {"eq", "in", "contains", "glob", "exists"}

def validate_condition(node, depth=0):
    if depth > 12 or not isinstance(node,dict): raise ValueError("invalid policy condition")
    if set(node) in ({"all"},{"any"}):
        children = next(iter(node.values()))
        if not isinstance(children,list) or not children or len(children)>64: raise ValueError("conditions require 1..64 children")
        for child in children: validate_condition(child,depth+1)
    else:
        if set(node) != {"field","op","value"} or not isinstance(node["field"],str) or node["op"] not in _OPS:
            raise ValueError("invalid policy predicate")
        if not node["field"].startswith(("event.","tool.","context.")): raise ValueError("unknown policy field namespace")
        if node["op"] == "in" and not isinstance(node["value"],list): raise ValueError("in requires a list")
        if node["op"] in {"glob","contains"} and not isinstance(node["value"],str): raise ValueError("text predicate requires a string")
        if node["op"] == "exists" and type(node["value"]) is not bool: raise ValueError("exists requires boolean")

def matches(node, facts):
    if "all" in node: return all(matches(x,facts) for x in node["all"])
    if "any" in node: return any(matches(x,facts) for x in node["any"])
    actual = facts
    for part in node["field"].split("."):
        if not isinstance(actual,dict) or part not in actual:
            actual = _MISSING
            break
        actual = actual[part]
    op, expected = node["op"],node["value"]
    if op == "exists": return (actual is not _MISSING) == expected
    if actual is _MISSING: return False
    if op == "eq": return actual == expected
    if op == "in": return actual in expected
    if op == "contains": return isinstance(actual,str) and expected.casefold() in actual.casefold()
    if op == "glob": return isinstance(actual,str) and fnmatch.fnmatchcase(actual.replace("\\","/").casefold(),expected.replace("\\","/").casefold())
    return False

class PolicyHandler:
    name = "tool_policy"
    def __init__(self, document: dict):
        if not isinstance(document,dict) or set(document) != {"version","default_decision","rules"}:
            raise ValueError("policy requires version, default_decision and rules")
        if not isinstance(document["version"],str) or not document["version"]: raise ValueError("version required")
        self.policy_version = document["version"]
        self.default_decision = Decision(document["default_decision"])
        self.rules = document["rules"]
        if not isinstance(self.rules,list) or len(self.rules)>128: raise ValueError("at most 128 policy rules")
        ids = set()
        for rule in self.rules:
            if not isinstance(rule,dict) or set(rule) != {"id","when","decision","severity","message"}:
                raise ValueError("invalid policy rule fields")
            if not isinstance(rule["id"],str) or not rule["id"] or rule["id"] in ids: raise ValueError("unique rule id required")
            ids.add(rule["id"])
            Decision(rule["decision"])
            if rule["severity"] not in {"INFO","WARN","ERROR","CRITICAL"} or not isinstance(rule["message"],str):
                raise ValueError("invalid policy severity/message")
            validate_condition(rule["when"])

    async def execute_with_context(self,event,context):
        start = time.perf_counter()
        if event.event_type not in {"tool.call.before","subagent.dispatch.before"}:
            return HandlerResult(self.name,"SKIPPED",0,decision=Decision.ALLOW), []
        facts = {"event":{"type":event.event_type,"payload":event.payload},
                 "tool":{"name":event.payload.get("tool_name"),"arguments":event.payload.get("arguments",{})},
                 "context":asdict(context) if context else {}}
        decisions, signals = [], []
        for rule in self.rules:
            if matches(rule["when"],facts):
                decisions.append(Decision(rule["decision"]))
                signals.append(RiskSignal(f"POLICY:{rule['id']}",rule["severity"],rule["message"],
                    source_ids=tuple(x.source_id for x in event.sources),evidence_event_ids=(event.event_id,),rule_id=rule["id"]))
        decision = max(decisions,key={Decision.ALLOW:0,Decision.REVIEW:1,Decision.BLOCK:2}.get) if decisions else self.default_decision
        if not signals and decision != Decision.ALLOW:
            signals.append(RiskSignal("POLICY_DEFAULT", "WARN", "No explicit tool policy matched"))
        return HandlerResult(self.name,"SUCCEEDED",(time.perf_counter()-start)*1000,decision=decision),signals

def load_policy(path: str) -> PolicyHandler:
    return PolicyHandler(json.loads(Path(path).read_text(encoding="utf-8")))
