"""Enforcing Claude Code PreToolUse bridge for Security Harness."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

HOOK_NAMESPACE = uuid.UUID("876524f4-6534-4c38-a68b-26f6408a7861")


def before_event_id(session_id: str, tool_use_id: str) -> str:
    return str(uuid.uuid5(HOOK_NAMESPACE, f"claude-code:{session_id}:{tool_use_id}:before"))


def _load_mapper():
    try:
        from security_harness.claude_tools import derive_tool_facts
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
        from security_harness.claude_tools import derive_tool_facts
    return derive_tool_facts


def build_event(hook_input: dict) -> dict:
    if not isinstance(hook_input, dict):
        raise TypeError("hook input must be a JSON object")
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict):
        raise TypeError("tool_input must be an object")
    tool_name = hook_input.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a nonempty string")
    derive = _load_mapper()
    cwd = hook_input.get("cwd")
    facts = derive(tool_name, tool_input, cwd=cwd if isinstance(cwd, str) else None)
    tool_use_id = hook_input.get("tool_use_id")
    if not isinstance(tool_use_id, str) or not tool_use_id:
        tool_use_id = str(uuid.uuid4())
    session_id = hook_input.get("session_id") or "hook-session"
    event_id = before_event_id(session_id, tool_use_id)
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "idempotency_key": f"claude-hook:{tool_use_id}",
        "event_type": "tool.call.before",
        "occurred_at": datetime.now(UTC).isoformat(),
        "agent": {"agent_id": "claude-code", "agent_type": "claude-code", "agent_version": "unknown"},
        "session_id": session_id,
        "payload": {"tool_name": tool_name, "arguments": tool_input, "cwd": cwd,
                    "tool_use_id": hook_input.get("tool_use_id"), "analysis": facts.analysis()},
        "impacts": [{"kind": i.kind, "target": i.target, "operation": i.operation} for i in facts.impacts],
        "metadata": {"adapter.claude_code.mode": "enforce", "adapter.claude_code.hook": "PreToolUse"},
    }


def to_hook_output(result: dict | None, error: Exception | str | None = None,
                   fail_mode: str = "closed") -> dict:
    if fail_mode not in {"closed", "open"}:
        fail_mode = "closed"
    failure = str(error) if error is not None else None
    decision = None
    if failure is None:
        if not isinstance(result, dict):
            failure = "invalid response"
        elif not {"decision", "risk_signals", "metadata"}.issubset(result):
            failure = "incomplete response"
        elif not isinstance(result["risk_signals"], list) or not isinstance(result["metadata"], dict):
            failure = "invalid response fields"
        elif result.get("metadata", {}).get("degraded"):
            failure = "server reported degraded evaluation"
        elif result.get("decision") not in {"ALLOW", "REVIEW", "BLOCK"}:
            failure = "invalid or unknown decision"
        else:
            decision = result["decision"]
    if failure is not None:
        if fail_mode == "open":
            return {}
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"security_harness unavailable (fail-closed): {failure}"[:1000],
        }}
    mapped = {"ALLOW": "allow", "REVIEW": "ask", "BLOCK": "deny"}[decision]
    signals = result.get("risk_signals", [])[:5]
    reason_parts = []
    for signal in signals:
        if isinstance(signal, dict):
            code, message = signal.get("code", "RISK"), signal.get("message", "")
            reason_parts.append(f"{code}: {message}".rstrip())
    reason = f"security_harness {decision}: " + "; ".join(reason_parts) if reason_parts else f"security_harness {decision}"
    approval_id = result.get("metadata", {}).get("approval_id")
    if mapped == "ask" and approval_id:
        suffix = f" (approval_id={approval_id})"
        reason = reason[:max(0, 1000 - len(suffix))] + suffix
    output = {"hookEventName": "PreToolUse", "permissionDecision": mapped,
              "permissionDecisionReason": reason[:1000]}
    return {"hookSpecificOutput": output}


def _post(url: str, timeout: float, event: dict) -> dict:
    headers = {"Content-Type": "application/json", "Idempotency-Key": event["idempotency_key"]}
    token = os.environ.get("HARNESS_API_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=json.dumps(event).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("server returned non-JSON response") from exc
    if not isinstance(result, dict):
        raise TypeError("server returned invalid response")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("HARNESS_URL", "http://127.0.0.1:8080/v1/events/evaluate"))
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    fail_mode = os.environ.get("HARNESS_HOOK_FAIL_MODE", "closed").lower()
    try:
        hook_input = json.load(sys.stdin)
        event = build_event(hook_input)
        result = _post(args.url, args.timeout, event)
        output = to_hook_output(result, fail_mode=fail_mode)
        signals = result.get("risk_signals", [])
        print(json.dumps(output, ensure_ascii=False))
        print(f"security_harness decision={result.get('decision')} signals={len(signals)}", file=sys.stderr)
    except (Exception, urllib.error.URLError, TimeoutError) as exc:
        output = to_hook_output(None, error=str(exc)[:300], fail_mode=fail_mode)
        print(json.dumps(output, ensure_ascii=False))
        print(f"security_harness hook_error={str(exc)[:300]}", file=sys.stderr)


if __name__ == "__main__":
    main()
