import asyncio, json, uuid
import pytest
from security_harness.audit import AuditRepository
from security_harness.context import ContextStore
from security_harness.domain import Decision, HarnessError, SecurityEvent
from security_harness.runtime import Runtime

def event(agent="a", session="s", seq=1, key=None, meta=None):
    return SecurityEvent.from_dict({"event_id": str(uuid.uuid4()), "idempotency_key": key or str(uuid.uuid4()), "event_type": "tool.call.before", "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": agent, "agent_type": "mock", "agent_version": "test"}, "session_id": session, "payload": {"tool_name": "shell"}, "metadata": meta or {}})

@pytest.mark.asyncio
async def test_ordering_idempotency_and_audit(tmp_path):
    repo = AuditRepository(str(tmp_path / "audit.db")); runtime = Runtime(repo)
    e1 = event(seq=1, key="same"); r1 = await runtime.evaluate(e1); r2 = await runtime.evaluate(e1)
    assert r1.decision == Decision.ALLOW and r2.metadata["idempotent_replay"] is True
    with pytest.raises(HarnessError) as err: await runtime.evaluate(event(seq=3))
    assert err.value.code == "SEQUENCE_GAP"
    row = await repo.get(r1.audit_id); assert row["status"] == "COMPLETED" and row["payload_digest"]

@pytest.mark.asyncio
async def test_cross_agent_parallel_and_same_lane_order(tmp_path):
    repo = AuditRepository(str(tmp_path / "audit.db")); runtime = Runtime(repo, concurrency=8)
    events = [event(agent=f"a{i}", seq=1, meta={"test.mock": {"delay_ms": 50}}) for i in range(4)]
    start = asyncio.get_running_loop().time(); results = await asyncio.gather(*(runtime.evaluate(e) for e in events)); elapsed = asyncio.get_running_loop().time() - start
    assert len(results) == 4 and elapsed < 0.18

@pytest.mark.asyncio
async def test_mock_failure_is_degraded_review_and_audited(tmp_path):
    repo = AuditRepository(str(tmp_path / "audit.db")); runtime = Runtime(repo)
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

