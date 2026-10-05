import asyncio
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
import uvicorn
from security_harness.audit import AuditRepository
from security_harness.main import create_fastapi_app
from security_harness.runtime import Runtime

def test_real_http_hook_two_submissions_in_same_session(tmp_path):
    repo=AuditRepository(str(tmp_path/"audit.db"))
    rt=Runtime(repo)
    app=create_fastapi_app(runtime=rt,api_token="hook-test",approval_token="human-test")
    listener=socket.socket()
    listener.bind(("127.0.0.1",0))
    port=listener.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,log_level="critical",loop="asyncio"))
    thread=threading.Thread(target=server.run,kwargs={"sockets":[listener]},daemon=True)
    thread.start()
    try:
        deadline=time.monotonic()+5
        while not server.started and time.monotonic()<deadline: time.sleep(.01)
        assert server.started
        bridge=pathlib.Path(__file__).parents[1]/"tools"/"claude_user_prompt_submit.py"
        env={**os.environ,"HARNESS_API_TOKEN":"hook-test"}
        for _ in range(2):
            result=subprocess.run([sys.executable,str(bridge),"--url",f"http://127.0.0.1:{port}/v1/events/evaluate"],
                input=json.dumps({"session_id":"same-hook-session","prompt":"Read README"}),
                text=True,capture_output=True,timeout=5,env=env)
            assert result.returncode==0 and json.loads(result.stdout)=={}
            assert "decision=ALLOW" in result.stderr and "hook_error" not in result.stderr
        rows=repo.conn.execute("SELECT seq,received_at FROM audit_event ORDER BY seq").fetchall()
        assert [r["seq"] for r in rows]==[1,2]
    finally:
        server.should_exit=True
        thread.join(timeout=5)
        listener.close()
        asyncio.run(repo.close())
        assert not thread.is_alive()
