"""Dependency-free acceptance smoke tests for environments without pytest."""
from __future__ import annotations
import asyncio, pathlib, sys, tempfile, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from security_harness.audit import AuditRepository
from security_harness.context import ContextStore
from security_harness.domain import Decision, HarnessError, SecurityEvent
from security_harness.runtime import Runtime

def make_event(agent="a", session="s", seq=1, key=None, meta=None):
    return SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": key or str(uuid.uuid4()), "event_type": "tool.call.before", "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": agent, "agent_type": "mock", "agent_version": "test"}, "session_id": session, "payload": {}, "metadata": meta or {}})

async def main():
    with tempfile.TemporaryDirectory() as td:
        repo = AuditRepository(str(pathlib.Path(td) / "audit.db")); rt = Runtime(repo, ContextStore(), concurrency=8)
        first = make_event(seq=1, key="same"); r1 = await rt.evaluate(first); r2 = await rt.evaluate(first)
        assert r1.decision == Decision.ALLOW and r2.metadata["idempotent_replay"]
        try: await rt.evaluate(make_event(seq=3))
        except HarnessError as e: assert e.code == "SEQUENCE_GAP"
        else: raise AssertionError("sequence gap not rejected")
        failed = await rt.evaluate(make_event(seq=2, meta={"test.mock": {"raise": "boom"}})); assert failed.decision == Decision.REVIEW and failed.metadata["degraded"]
        events = [make_event(agent=f"a{i}", meta={"test.mock": {"delay_ms": 50}}) for i in range(4)]
        start = asyncio.get_running_loop().time(); await asyncio.gather(*(rt.evaluate(e) for e in events)); assert asyncio.get_running_loop().time() - start < .18
        snap = await rt.context.update("a:s", {"x": 1})
        try: await rt.context.update("a:s", {"x": 2}, expected_version=0)
        except HarnessError as e: assert e.code == "CONTEXT_VERSION_CONFLICT"
        else: raise AssertionError("context conflict not rejected")
        await repo.close()
        print("Stage 1 smoke tests: PASS")

if __name__ == "__main__": asyncio.run(main())
