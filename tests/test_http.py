"""Exercise the actual ASGI app without an extra HTTP client dependency."""
import asyncio
import json
import pytest
from security_harness.audit import AuditRepository
from security_harness.main import create_fastapi_app
from security_harness.pipeline import Pipeline
from security_harness.runtime import Runtime
from test_infrastructure import Fixed, raw
from security_harness.domain import Decision

async def request(app,path,body=None,headers=None,method="POST"):
    payload=json.dumps(body).encode() if body is not None else b""
    sent=[]
    consumed=False
    completed=asyncio.Event()
    async def receive():
        nonlocal consumed
        if not consumed:
            consumed=True
            return {"type":"http.request","body":payload,"more_body":False}
        await completed.wait()
        return {"type":"http.disconnect"}
    async def send(message):
        sent.append(message)
        if message["type"]=="http.response.body" and not message.get("more_body"): completed.set()
    scope={"type":"http","asgi":{"version":"3.0","spec_version":"2.4"},"http_version":"1.1",
           "method":method,"scheme":"http","path":path,"raw_path":path.encode(),"query_string":b"",
           "headers":[(k.lower().encode(),v.encode()) for k,v in (headers or {}).items()],
           "server":("test",80),"client":("test",1),"root_path":""}
    await app(scope,receive,send)
    status=next(m["status"] for m in sent if m["type"]=="http.response.start")
    data=b"".join(m.get("body",b"") for m in sent if m["type"]=="http.response.body")
    return status,json.loads(data)

@pytest.mark.asyncio
async def test_http_auth_sequence_health_audit_and_trace(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")))
    app=create_fastapi_app(runtime=rt,api_token="adapter-test",approval_token="human-test")
    status,_=await request(app,"/v1/events/evaluate",raw())
    assert status==401
    headers={"Authorization":"Bearer adapter-test"}
    results=[]
    for _ in range(2):
        status,result=await request(app,"/v1/events/evaluate",raw(),headers)
        assert status==200
        results.append(result)
    status,health=await request(app,"/healthz",method="GET")
    assert status==200 and health["handlers"]==["observation"]
    status,audit=await request(app,f"/v1/audit/{results[-1]['audit_id']}",headers=headers,method="GET")
    assert status==200 and audit["seq"]==2
    status,trace=await request(app,"/v1/sessions/main:s/trace",headers=headers,method="GET")
    assert status==200 and len(trace["nodes"])==2
    await rt.audit.close()

@pytest.mark.asyncio
async def test_http_approval_needs_separate_trusted_credential(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")),pipeline=Pipeline(Fixed("review",Decision.REVIEW)))
    app=create_fastapi_app(runtime=rt,api_token="adapter-test",approval_token="human-test")
    headers={"Authorization":"Bearer adapter-test"}
    status,result=await request(app,"/v1/events/evaluate",raw("tool.call.before",{"tool_name":"exec"}),headers)
    assert status==200
    path=f"/v1/approvals/{result['metadata']['approval_id']}/resolve"
    body={"approved":True,"actor":"tester"}
    assert (await request(app,path,body,headers))[0]==403
    headers["X-Approval-Token"]="human-test"
    assert (await request(app,path,body,headers))[0]==200
    assert (await request(app,path,body,headers))[0]==409
    await rt.audit.close()

@pytest.mark.asyncio
async def test_http_invalid_request_is_domain_error(tmp_path):
    rt=Runtime(AuditRepository(str(tmp_path/"audit.db")))
    app=create_fastapi_app(runtime=rt,api_token="",approval_token="")
    status,result=await request(app,"/v1/events/evaluate",[])
    assert status==400 and result["error"]["code"]=="INVALID_REQUEST"
    status,_=await request(app,"/v1/events/evaluate",{},headers={"Content-Length":str(1024*1024+1)})
    assert status==413
    await rt.audit.close()
