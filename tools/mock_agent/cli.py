from __future__ import annotations
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
import argparse, asyncio, time, uuid
from security_harness.audit import AuditRepository
from security_harness.context import ContextStore
from security_harness.domain import SecurityEvent
from security_harness.runtime import Runtime

async def run(args):
    runtime = Runtime(AuditRepository(args.db), ContextStore(), concurrency=args.concurrency)
    started = time.perf_counter(); all_results = []
    async def one(agent: int):
        session = f"s-{agent}"; results = []
        pattern = ["agent.session.started", "user.prompt.submitted", "tool.call.before", "tool.call.after", "agent.session.ended"]
        for seq in range(1, args.events_per_agent + 1):
            event = SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": f"mock-{agent}-{seq}", "event_type": pattern[(seq-1)%len(pattern)], "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": f"agent-{agent}", "agent_type": "mock", "agent_version": "stage1"}, "session_id": session, "payload": {}, "metadata": {"test.mock": {"delay_ms": 1}}})
            results.append(await runtime.evaluate(event))
        return results
    all_results = await asyncio.gather(*(one(i) for i in range(args.agents)))
    terminal = sum(1 for group in all_results for r in group if r.metadata.get("degraded") is False)
    total = sum(len(x) for x in all_results); print({"agents": args.agents, "events": total, "terminal_ratio": terminal/total, "elapsed_ms": (time.perf_counter()-started)*1000})

def main():
    p=argparse.ArgumentParser(); p.add_argument("--agents", type=int, default=8); p.add_argument("--events-per-agent", type=int, default=20); p.add_argument("--concurrency", type=int, default=16); p.add_argument("--db", default="data/mock-agent.db"); args=p.parse_args(); asyncio.run(run(args))
if __name__ == "__main__": main()
