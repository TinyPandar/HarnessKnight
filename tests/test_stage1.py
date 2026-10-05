import asyncio, json, uuid
import pytest
from security_harness.audit import AuditRepository
from security_harness.context import ContextStore
from security_harness.domain import Decision, HarnessError, SecurityEvent
from security_harness.runtime import Runtime
from security_harness.pipeline import Pipeline, MockRuleHandler

def event(agent="a", session="s", seq=1, key=None, meta=None):
    return SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": key or str(uuid.uuid4()), "event_type": "tool.call.before", "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": agent, "agent_type": "mock", "agent_version": "test"}, "session_id": session, "payload": {"tool_name": "shell"}, "metadata": meta or {}})

@pytest.mark.asyncio
async def test_ordering_idempotency_and_audit(tmp_path):
    repo = AuditRepository(str(tmp_path / "audit.db")); runtime = Runtime(repo, pipeline=Pipeline(MockRuleHandler()))
    e1 = event(seq=1, key="same"); r1 = await runtime.evaluate(e1); r2 = await runtime.evaluate(e1)
    assert r1.decision == Decision.ALLOW and r2.metadata["idempotent_replay"] is True
    with pytest.raises(HarnessError) as err: await runtime.evaluate(event(seq=3))
    assert err.value.code == "SEQUENCE_GAP"
    row = await repo.get(r1.audit_id); assert row["status"] == "COMPLETED" and row["payload_digest"]

@pytest.mark.asyncio
async def test_cross_agent_handlers_overlap(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()
    active = set()
    class ParallelProbe(MockRuleHandler):
        async def execute(self, item):
            active.add(item.agent.agent_id)
            if len(active) == 4: entered.set()
            await release.wait()
            return await super().execute(item)
    repo = AuditRepository(str(tmp_path / "audit.db"))
    runtime = Runtime(repo, concurrency=8, request_timeout_ms=10000,
                      pipeline=Pipeline(ParallelProbe(), handler_timeout_ms=10000))
    tasks = [asyncio.create_task(runtime.evaluate(event(agent=f"a{i}"))) for i in range(4)]
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert len(active) == 4  # All four handlers entered before any was released.
    finally:
        release.set()
        results = await asyncio.gather(*tasks)
        await repo.close()
    assert len(results) == 4 and all(not r.metadata["degraded"] for r in results)

@pytest.mark.asyncio
async def test_mock_failure_is_degraded_review_and_audited(tmp_path):
    repo = AuditRepository(str(tmp_path / "audit.db")); runtime = Runtime(repo, pipeline=Pipeline(MockRuleHandler()))
    result = await runtime.evaluate(event(meta={"test.mock": {"raise": "boom"}}))
    assert result.decision == Decision.REVIEW and result.metadata["degraded"] is True
    assert (await repo.get(result.audit_id))["status"] == "FAILED"

def test_validation_boundaries():
    with pytest.raises(HarnessError) as err: SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": "x", "event_type": "tool.call.before", "seq": 1, "agent": {"agent_id":"a"}, "session_id":"s", "unknown": 1})
    assert err.value.code == "INVALID_EVENT"

@pytest.mark.asyncio
async def test_context_optimistic_version(tmp_path):
    store = ContextStore(); snap = await store.update("a:s", {"x": 1})
    with pytest.raises(HarnessError) as err: await store.update("a:s", {"x": 2}, expected_version=0)
    assert err.value.code == "CONTEXT_VERSION_CONFLICT" and snap.version == 1
