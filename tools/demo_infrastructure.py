"""Safe infrastructure demo: tools are in-memory fixtures, no file/network effects."""
from __future__ import annotations
import argparse
import asyncio
import json
import pathlib
import sys
import tempfile
import uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"src"))
from security_harness.bootstrap import HarnessConfig, build_runtime
from security_harness.domain import HarnessError, Impact, SourceSpan
from security_harness.gateway import ToolGateway, ToolOutput
from security_harness.provenance import build_trace

def event(kind,payload,**extra):
    return {"event_id":str(uuid.uuid4()),"idempotency_key":str(uuid.uuid4()),"event_type":kind,
            "agent":{"agent_id":"demo-agent"},"session_id":"demo-session","payload":payload,**extra}

async def run(db,output):
    policy=pathlib.Path(__file__).resolve().parents[1]/"examples"/"policies"/"demo.json"
    rt=build_runtime(HarnessConfig(db=db,mode="protect",policy_path=str(policy)))
    calls=[]
    async def read(args):
        calls.append("fs.read")
        return ToolOutput("Demo README",resource={"uri":"file://README.md","sensitivity":"public"},
            sources=(SourceSpan("readme-content","tool_result",char_start=0,char_end=11),),
            impacts=(Impact("file","README.md","read"),))
    async def write(args): calls.append("fs.write"); return {"ok":True}
    async def fetch(args): calls.append("net.fetch"); return {"fixture":True}
    gateway=ToolGateway(rt,{"fs.read":read,"fs.write":write,"net.fetch":fetch})
    async def confirm(call,result):
        print(json.dumps({"demo_confirmation":result.metadata["approval_id"],"tool":call.payload["tool_name"],"approved":True}))
        return True
    try:
        await rt.submit(event("agent.task.started",{"intent":"Read project README"}))
        await rt.submit(event("agent.plan.updated",{"steps":["Read README.md"]}))
        await gateway.call(event("tool.call.before",{"tool_name":"fs.read","arguments":{"path":"README.md"}}))
        try:
            await gateway.call(event("tool.call.before",{"tool_name":"fs.write","arguments":{"path":"~/.ssh/config","content":"fixture"}}))
        except HarnessError as exc:
            assert exc.code=="TOOL_BLOCKED"
            print(json.dumps({"blocked":exc.code}))
        await gateway.call(event("tool.call.before",{"tool_name":"net.fetch","arguments":{"url":"https://example.invalid"}}),confirm=confirm)
        assert calls==["fs.read","net.fetch"]
        graph=await build_trace(rt.audit,"demo-agent:demo-session")
        if output:
            target=pathlib.Path(output).resolve()
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text(json.dumps(graph,ensure_ascii=False,indent=2),encoding="utf-8")
        print(json.dumps({"executed":calls,"trace_nodes":len(graph["nodes"]),"trace_edges":len(graph["edges"]),"pass":True}))
    finally: await rt.audit.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--trace-output")
    args=parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(run(str(pathlib.Path(directory)/"audit.db"),args.trace_output))

if __name__ == "__main__": main()
