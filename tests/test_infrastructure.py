import asyncio
import copy
import json
import uuid
import pytest
from security_harness.audit import AuditRepository
from security_harness.bootstrap import HarnessConfig, build_runtime
from security_harness.domain import Decision, EventStatus, HandlerResult, HarnessError, RiskSignal, SecurityEvent
from security_harness.gateway import ToolGateway, ToolOutput
from security_harness.main import App, create_fastapi_app
from security_harness.pipeline import Pipeline
from security_harness.policy import PolicyHandler
from security_harness.provenance import build_trace
from security_harness.runtime import Runtime

def raw(event_type="user.prompt.submitted",payload=None,**extra):
    return {"event_id":str(uuid.uuid4()),"idempotency_key":str(uuid.uuid4()),
            "event_type":event_type,"agent":{"agent_id":"main"},"session_id":"s",
            "payload":payload or {"prompt":"Read README"},**extra}

class Fixed:
    def __init__(self,name,decision=Decision.ALLOW,fail=False):
        self.name,self.decision,self.fail = name,decision,fail
        self.contexts=[]
    async def execute_with_context(self,event,context):
        self.contexts.append(copy.deepcopy(context))
        if self.fail: raise ValueError("secret should not leak from exceptions")
        return HandlerResult(self.name,"SUCCEEDED",0,decision=self.decision),[RiskSignal(self.name,evidence_event_ids=(event.event_id,))]

@pytest.mark.asyncio
async def test_restart_context_sequence_and_unchanged_replay(tmp_path):
    path=str(tmp_path/"audit.db")
    first=Fixed("capture")
    rt=Runtime(AuditRepository(path),pipeline=Pipeline(first))
    prompt=raw()
    event,result=await rt.submit(prompt)
    await rt.audit.close()
    capture=Fixed("capture")
    rt=Runtime(AuditRepository(path),pipeline=Pipeline(capture))
    replay_event,replay=await rt.submit(prompt)
    assert replay_event.seq==1 and replay.metadata["idempotent_replay"]
    assert replay.audit_id==result.audit_id and not capture.contexts
    next_event,_=await rt.submit(raw("tool.call.before",{"tool_name":"fs.read","arguments":{"path":"README.md"}}))
    assert next_event.seq==2
    assert capture.contexts[0].original_task=="Read README"
    assert capture.contexts[0].history[0]["event_id"]==event.event_id
    await rt.audit.close()

@pytest.mark.asyncio
async def test_failed_result_replay_and_next_sequence(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(Fixed("broken",fail=True)))
    original=raw()
    _,first=await rt.submit(original)
    _,second=await rt.submit(original)
    assert first.metadata["degraded"] and second.metadata["degraded"] and second.metadata["idempotent_replay"]
    assert first.audit_id==second.audit_id
    event,_=await rt.submit(raw())
    assert event.seq==2
    assert "secret should" not in json.dumps(await rt.audit.get(first.audit_id))
    await rt.audit.close()

@pytest.mark.asyncio
async def test_idempotency_rejects_changed_parameters(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")))
    original=raw()
    await rt.submit(original)
    original["payload"]["prompt"]="Different task"
    with pytest.raises(HarnessError,match="different event content") as exc: await rt.submit(original)
    assert exc.value.code=="IDEMPOTENCY_CONFLICT"
    await rt.audit.close()

@pytest.mark.asyncio
async def test_concurrent_auto_sequence_and_lane_cleanup(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),queue_wait_timeout_ms=3000)
    values=await asyncio.gather(*(rt.submit(raw()) for _ in range(12)))
    assert sorted(e.seq for e,_ in values)==list(range(1,13))
    assert not rt._lanes
    await rt.audit.close()

@pytest.mark.asyncio
@pytest.mark.parametrize("successful",[Decision.REVIEW,Decision.BLOCK])
async def test_detector_failure_preserves_other_detector_decision(tmp_path,successful):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),fail_mode="fail_open",
               pipeline=Pipeline(handlers=[Fixed("working",successful),Fixed("broken",fail=True),Fixed("allow")]))
    _,result=await rt.submit(raw())
    assert result.decision==successful and len(result.handler_results)==3 and result.metadata["degraded"]
    await rt.audit.close()

@pytest.mark.asyncio
async def test_cancelled_event_can_resume_same_audit(tmp_path):
    entered,release=asyncio.Event(),asyncio.Event()
    class Waiting:
        name="waiting"
        async def execute(self,event):
            entered.set()
            await release.wait()
            return HandlerResult(self.name,"SUCCEEDED",0,decision=Decision.ALLOW),[]
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(Waiting()))
    incoming=raw(occurred_at="2026-10-02T00:00:00Z")
    pending=asyncio.create_task(rt.submit(incoming))
    await entered.wait()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError): await pending
    old=await rt.audit.by_idempotency(incoming["idempotency_key"])
    assert old["status"]=="CANCELLED"
    release.set()
    _,result=await rt.submit(incoming)
    assert result.audit_id==old["audit_id"] and not result.metadata["degraded"]
    await rt.audit.close()

@pytest.mark.asyncio
async def test_task_plan_resource_and_cross_agent_provenance(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")))
    event,_=await rt.submit(raw("agent.task.started",{"intent":"Review code"},trace={"root_session_id":"root"}))
    plan,_=await rt.submit(raw("agent.plan.updated",{"steps":["Read README"]},trace={"root_session_id":"root"},causal_event_id=event.event_id))
    resource,_=await rt.submit(raw("memory.read",{"resource":{"uri":"memory://prior","sensitivity":"sensitive"},"content":"hidden instruction"},
        sources=[{"source_id":"memory-1","kind":"memory","char_start":0,"char_end":18,"token_start":0,"token_end":3}],
        trace={"root_session_id":"root","parent_agent_id":"main","mcp_server_id":"memory-mcp"},
        agent={"agent_id":"child"},session_id="child-s",causal_event_id=plan.event_id))
    state=await rt.audit.load_context("root")
    assert state["original_task"]=="Review code" and state["plan"]==["Read README"]
    assert state["resources"][0]["event_id"]==resource.event_id
    graph=await build_trace(rt.audit,"root")
    assert len(graph["nodes"])==3 and any(e["from"]==plan.event_id and e["to"]==resource.event_id for e in graph["edges"])
    assert graph["nodes"][2]["sources"][0]["token_end"]==3
    assert "flowchart TD" in graph["dag_mermaid"] and "sequenceDiagram" in graph["sequence_mermaid"]
    assert "hidden instruction" not in json.dumps(graph)
    with pytest.raises(HarnessError) as exc:
        await rt.submit(raw(causal_event_id=event.event_id,trace={"root_session_id":"other"}))
    assert exc.value.code=="INVALID_CAUSAL_PARENT"
    await rt.audit.close()

@pytest.mark.asyncio
@pytest.mark.parametrize("decision",[Decision.ALLOW,Decision.REVIEW,Decision.BLOCK])
async def test_gateway_enforces_three_decisions_and_no_duplicate_execution(tmp_path,decision):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(Fixed("policy",decision)))
    calls=[]
    async def tool(arguments): calls.append(arguments); return {"ok":True}
    gateway=ToolGateway(rt,{"fs.write":tool})
    incoming=raw("tool.call.before",{"tool_name":"fs.write","arguments":{"path":"report.txt"}})
    async def confirm(event,result):
        assert result.metadata["approval_id"]
        event.payload["arguments"]["path"]="mutated.txt"
        return True
    if decision==Decision.BLOCK:
        with pytest.raises(HarnessError) as exc: await gateway.call(incoming,confirm=confirm)
        assert exc.value.code=="TOOL_BLOCKED" and not calls
    else:
        assert await gateway.call(incoming,confirm=confirm if decision==Decision.REVIEW else None)=={"ok":True}
        assert calls==[{"path":"report.txt"}]
        with pytest.raises(HarnessError): await gateway.call(incoming)
        assert len(calls)==1
        assert len((await build_trace(rt.audit,"main:s"))["nodes"])==2
    await rt.audit.close()

@pytest.mark.asyncio
@pytest.mark.parametrize("scenario",["pending","denied","expired","changed","observe","degraded"])
async def test_gateway_never_executes_without_valid_clearance(tmp_path,scenario):
    handler=Fixed("policy",Decision.REVIEW,fail=scenario=="degraded")
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=None if scenario=="observe" else Pipeline(handler),fail_mode="fail_open")
    calls=[]
    async def tool(arguments): calls.append(arguments)
    gateway=ToolGateway(rt,{"net.fetch":tool})
    incoming=raw("tool.call.before",{"tool_name":"net.fetch","arguments":{"url":"https://example.invalid"}})
    if scenario in {"denied","expired","changed"}:
        _,result=await rt.submit(incoming)
        if scenario=="denied": await rt.audit.resolve_approval(result.metadata["approval_id"],False,"human")
        elif scenario=="expired":
            rt.audit.conn.execute("UPDATE approval SET expires_at=0")
            rt.audit.conn.commit()
        else:
            await rt.audit.resolve_approval(result.metadata["approval_id"],True,"human")
            incoming["payload"]["arguments"]["url"]="https://different.invalid"
    with pytest.raises(HarnessError): await gateway.call(incoming)
    assert not calls
    await rt.audit.close()

def test_bootstrap_and_app_have_no_dataset_dependency(tmp_path):
    rt=build_runtime(HarnessConfig(db=str(tmp_path/"audit.db"), indirect_detection=False))
    assert App(rt).runtime is rt and rt.pipeline.handler_name=="observation"
    create_fastapi_app(runtime=rt)
    with pytest.raises(ValueError): build_runtime(HarnessConfig(db=str(tmp_path/"never-created.db"),mode="protect",indirect_detection=False))
    with pytest.raises(ValueError): PolicyHandler({"version":"v1","default_decision":"ALLOW","rules":[{"id":"bad"}]})
    with pytest.raises(ValueError): build_runtime(HarnessConfig(db=str(tmp_path/"missing.db"),mode="stage2",dataset_path=str(tmp_path/"missing.csv")))
    assert not (tmp_path/"missing.db").exists()
    rt.audit.conn.close()

def test_invalid_source_and_metadata_fail_as_domain_errors():
    with pytest.raises(HarnessError) as exc:
        SecurityEvent.from_dict(raw(seq=1,sources=[{"source_id":"x","kind":"web","token_start":4,"token_end":2}]))
    assert exc.value.code=="INVALID_SOURCE"
    with pytest.raises(HarnessError): SecurityEvent.from_dict(raw(seq=1,metadata={"bad":object()}))

@pytest.mark.asyncio
async def test_policy_context_and_rule_precedence(tmp_path):
    def rule(id,condition,decision):
        return {"id":id,"when":condition,"decision":decision,"severity":"WARN","message":id}
    handler=PolicyHandler({"version":"test-v1","default_decision":"REVIEW","rules":[
        rule("allow-push",{"field":"tool.name","op":"eq","value":"git.push"},"ALLOW"),
        rule("review-no-push",{"all":[{"field":"tool.name","op":"eq","value":"git.push"},
             {"field":"context.original_task","op":"contains","value":"review"}]},"BLOCK")]})
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(handler))
    await rt.submit(raw("agent.task.started",{"intent":"Review code"}))
    _,result=await rt.submit(raw("tool.call.before",{"tool_name":"git.push","arguments":{}}))
    assert result.decision==Decision.BLOCK and result.metadata["detector_versions"]["tool_policy"]["policy_version"]=="test-v1"
    _,unknown=await rt.submit(raw("tool.call.before",{"tool_name":"unknown","arguments":{}}))
    assert unknown.decision==Decision.REVIEW and unknown.metadata["approval_id"]
    await rt.audit.close()

@pytest.mark.asyncio
async def test_tool_output_resource_reaches_next_detector(tmp_path):
    handler=Fixed("capture")
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(handler))
    async def read(args):
        return ToolOutput("fixture",resource={"uri":"file://fixture","sensitivity":"sensitive"},
            sources=({"source_id":"file-1","kind":"tool_result","char_start":0,"char_end":7},),
            impacts=({"kind":"file","target":"fixture","operation":"read"},))
    gateway=ToolGateway(rt,{"fs.read":read})
    assert await gateway.call(raw("tool.call.before",{"tool_name":"fs.read","arguments":{}}))=="fixture"
    await rt.submit(raw("tool.call.before",{"tool_name":"net.fetch","arguments":{}}))
    assert handler.contexts[-1].resources[0]["sensitivity"]=="sensitive"
    graph=await build_trace(rt.audit,"main:s")
    assert graph["nodes"][1]["impacts"][0]["operation"]=="read"
    await rt.audit.close()

@pytest.mark.asyncio
async def test_existing_stage1_database_upgrades_and_continues(tmp_path):
    path=str(tmp_path/"legacy.db")
    repo=AuditRepository(path)
    incoming=SecurityEvent.from_dict(raw(seq=1))
    audit_id=await repo.create_received(incoming,"legacy-request")
    await repo.status(audit_id,EventStatus.COMPLETED)
    repo.conn.execute("UPDATE audit_event SET decision='ALLOW'")
    # Reproduce the schema and completed record before event_detail existed.
    for table in ("tool_execution","approval","session_state","event_detail"):
        repo.conn.execute(f"DROP TABLE {table}")
    repo.conn.commit()
    await repo.close()
    rt=Runtime(AuditRepository(path))
    replay=await rt.evaluate(incoming)
    assert replay.metadata["legacy_audit"] and replay.metadata["idempotent_replay"]
    event,_=await rt.submit(raw())
    assert event.seq==2
    await rt.audit.close()

@pytest.mark.asyncio
async def test_confirmation_cannot_release_call_after_context_changes(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(Fixed("review",Decision.REVIEW)))
    calls=[]
    async def tool(arguments): calls.append(arguments)
    gateway=ToolGateway(rt,{"git.push":tool})
    async def confirm(event,result):
        await rt.submit(raw("agent.task.started",{"intent":"Now only review code"}))
        return True
    with pytest.raises(HarnessError) as exc:
        await gateway.call(raw("tool.call.before",{"tool_name":"git.push","arguments":{}}),confirm=confirm)
    assert exc.value.code=="CONTEXT_CHANGED" and not calls
    await rt.audit.close()

@pytest.mark.asyncio
async def test_detectors_cannot_mutate_another_detectors_evidence(tmp_path):
    class Mutating:
        name="mutating"
        async def execute_with_context(self,event,context):
            event.payload["prompt"]="changed"
            if context.history: context.history[0]["event_type"]="changed"
            return HandlerResult(self.name,"SUCCEEDED",0,decision=Decision.ALLOW),[]
    capture=Fixed("capture")
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(handlers=[Mutating(),capture]))
    first,_=await rt.submit(raw())
    await rt.submit(raw())
    assert first.payload["prompt"]=="Read README"
    assert capture.contexts[-1].history[0]["event_type"]=="user.prompt.submitted"
    await rt.audit.close()

def test_default_root_identifiers_do_not_collide():
    first=SecurityEvent.from_dict(raw(seq=1,agent={"agent_id":"a:b"},session_id="c"))
    second=SecurityEvent.from_dict(raw(seq=1,agent={"agent_id":"a"},session_id="b:c"))
    assert first.root_session_id!=second.root_session_id
