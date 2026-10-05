"""Minimal Claude Code UserPromptSubmit bridge. Monitor-only by default."""
from __future__ import annotations
import argparse, json, os, sys, urllib.request, uuid
from datetime import datetime, timezone

def main():
    p=argparse.ArgumentParser(); p.add_argument("--url", default="http://127.0.0.1:8080/v1/events/evaluate"); p.add_argument("--timeout", type=float, default=2.0); args=p.parse_args()
    try:
        incoming=json.load(sys.stdin); prompt=incoming.get("prompt")
        if not isinstance(prompt, str): raise ValueError("UserPromptSubmit input must contain string prompt")
        body={"schema_version":"1.0","event_id":str(uuid.uuid4()),"idempotency_key":f"claude-hook:{uuid.uuid4()}","event_type":"user.prompt.submitted","occurred_at":datetime.now(timezone.utc).isoformat(),"agent":{"agent_id":"claude-code","agent_type":"claude-code","agent_version":"unknown"},"session_id":incoming.get("session_id", "hook-session"),"payload":{"prompt":prompt},"metadata":{"adapter.claude_code.mode":"monitor"}}
        headers={"Content-Type":"application/json","Idempotency-Key":body["idempotency_key"]}
        if os.environ.get("HARNESS_API_TOKEN"): headers["Authorization"] = "Bearer " + os.environ["HARNESS_API_TOKEN"]
        request=urllib.request.Request(args.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=args.timeout) as response: result=json.load(response)
        print(json.dumps({}, ensure_ascii=False)); print(f"security_harness decision={result.get('decision')} signals={len(result.get('risk_signals', []))}", file=sys.stderr)
    except Exception as exc:
        print(json.dumps({}, ensure_ascii=False)); print(f"security_harness hook_error={exc}", file=sys.stderr)

if __name__ == "__main__": main()
