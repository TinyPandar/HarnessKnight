import copy
import uuid

import pytest

from security_harness.audit import AuditRepository
from security_harness.domain import HarnessError
from security_harness.pipeline import MockRuleHandler, Pipeline
from security_harness.runtime import Runtime


def raw(payload=None, event_type="tool.call.before", key="same"):
    return {"event_id":str(uuid.uuid4()),"idempotency_key":key,"event_type":event_type,
      "agent":{"agent_id":"agent"},"session_id":"s","payload":payload or {"tool_name":"Read","arguments":{}},
      "metadata":{},"impacts":[]}

@pytest.mark.asyncio
async def test_content_fingerprint_replay_and_conflict(tmp_path):
    runtime=Runtime(AuditRepository(str(tmp_path/"db")),pipeline=Pipeline(MockRuleHandler()))
    first=raw(); _, a=await runtime.submit(first)
    again={**first,"event_id":str(uuid.uuid4()),"occurred_at":"later"}
    returned,b=await runtime.submit(again)
    assert b.metadata["idempotent_replay"] and b.audit_id == a.audit_id and returned.event_id == first["event_id"]
    changed={**again,"payload":{"tool_name":"Write","arguments":{}}}
    with pytest.raises(HarnessError) as error: await runtime.submit(changed)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    await runtime.audit.close()

@pytest.mark.asyncio
async def test_replayed_review_approval_binds_event_id_and_content(tmp_path):
    runtime=Runtime(AuditRepository(str(tmp_path/"db")),pipeline=Pipeline(MockRuleHandler()))
    event={**raw(),"metadata":{"test.mock":{"action":"review"}}}
    _returned,result=await runtime.submit(event)
    replay,repeated=await runtime.submit({**event,"event_id":str(uuid.uuid4()),"occurred_at":"later"})
    assert repeated.metadata["approval_id"] == result.metadata["approval_id"]
    await runtime.audit.resolve_approval(result.metadata["approval_id"],True,"user")
    await runtime.audit.claim_execution(replay,repeated)
    changed=copy.deepcopy(replay); object.__setattr__(changed,"event_id",str(uuid.uuid4()))
    with pytest.raises(HarnessError,match="execution event id"): await runtime.audit.claim_execution(changed,repeated)
    changed_payload=copy.deepcopy(replay)
    object.__setattr__(changed_payload,"payload",{"tool_name":"Write","arguments":{}})
    with pytest.raises(HarnessError,match="execution must match"): await runtime.audit.claim_execution(changed_payload,repeated)
    await runtime.audit.close()
