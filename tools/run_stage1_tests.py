"""Dependency-free acceptance smoke tests for environments without pytest."""
from __future__ import annotations
import asyncio, pathlib, sys, tempfile, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from security_harness.audit import AuditRepository
from security_harness.context import ContextStore
from security_harness.domain import Decision, HarnessError, SecurityEvent
from security_harness.runtime import Runtime
from security_harness.pipeline import Pipeline, MockRuleHandler

def make_event(agent="a", session="s", seq=1, key=None, meta=None):
    return SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": key or str(uuid.uuid4()), "event_type": "tool.call.before", "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": agent, "agent_type": "mock", "agent_version": "test"}, "session_id": session, "payload": {}, "metadata": meta or {}})

async def main():
    with tempfile.TemporaryDirectory() as td:
        repo = AuditRepository(str(pathlib.Path(td) / "audit.db")); rt = Runtime(repo, ContextStore(), concurrency=8, pipeline=Pipeline(MockRuleHandler()))
        first = make_event(seq=1, key="same"); r1 = await rt.evaluate(first); r2 = await rt.evaluate(first)
        assert r1.decision == Decision.ALLOW and r2.metadata["idempotent_replay"]
        try: await rt.evaluate(make_event(seq=3))
        except HarnessError as e: assert e.code == "SEQUENCE_GAP"
        else: raise AssertionError("sequence gap not rejected")
        failed = await rt.evaluate(make_event(seq=2, meta={"test.mock": {"raise": "boom"}})); assert failed.decision == Decision.REVIEW and failed.metadata["degraded"]
        entered, release = asyncio.Event(), asyncio.Event()
        active = set()
        class ParallelProbe(MockRuleHandler):
            async def execute(self, item):
                active.add(item.agent.agent_id)
                if len(active) == 4: entered.set()
                await release.wait()
                return await super().execute(item)
        rt.pipeline = Pipeline(ParallelProbe(), handler_timeout_ms=10000)
        rt.request_timeout_ms = 10000
        tasks = [asyncio.create_task(rt.evaluate(make_event(agent=f"a{i}"))) for i in range(4)]
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert len(active) == 4
        finally:
            release.set()
            await asyncio.gather(*tasks)
        snap = await rt.context.update("a:s", {"x": 1})
        try: await rt.context.update("a:s", {"x": 2}, expected_version=0)
        except HarnessError as e: assert e.code == "CONTEXT_VERSION_CONFLICT"
        else: raise AssertionError("context conflict not rejected")
        await repo.close()
        print("Stage 1 smoke tests: PASS")

if __name__ == "__main__": asyncio.run(main())
