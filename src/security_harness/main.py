from __future__ import annotations
import argparse
import hmac
import json
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from .bootstrap import HarnessConfig, build_runtime
from .domain import HarnessError
from .provenance import build_trace
from .runtime import Runtime

class App:
    """Application behavior only. Dataset I/O belongs to bootstrap."""
    def __init__(self,runtime: Runtime):
        self.runtime = runtime
        self.audit = runtime.audit

def create_fastapi_app(db: str | None = None, *, runtime: Runtime | None = None,
                       dataset_path: str | None = None,rules_path: str | None = None,
                       policy_path: str | None = None,mode: str = "observe", indirect_detection: bool = True,
                       api_token: str | None = None,approval_token: str | None = None):
    if runtime is not None and any(x is not None for x in (db,dataset_path,rules_path,policy_path)):
        raise ValueError("injected runtime cannot be combined with bootstrap paths")
    api_token = api_token if api_token is not None else os.environ.get("HARNESS_API_TOKEN")
    approval_token = approval_token if approval_token is not None else os.environ.get("HARNESS_APPROVAL_TOKEN")
    if api_token and approval_token and hmac.compare_digest(api_token,approval_token):
        raise ValueError("API and approval credentials must differ")
    owned = runtime is None
    if runtime is None:
        runtime = build_runtime(HarnessConfig(db=db or "data/audit.db",mode=mode,dataset_path=dataset_path,
                                             rules_path=rules_path,policy_path=policy_path,indirect_detection=indirect_detection))
    state = App(runtime)

    @asynccontextmanager
    async def lifespan(_):
        yield
        if owned: await state.audit.close()

    api = FastAPI(title="Agent Security Harness",version="0.3.0",lifespan=lifespan)
    api.state.harness = state

    @api.exception_handler(HarnessError)
    async def harness_error(_request,exc):
        return JSONResponse(status_code=exc.status,content={"error":{"code":exc.code,"message":exc.message,
            "retryable":exc.retryable,"details":exc.details}})

    @api.middleware("http")
    async def adapter_auth(request,call_next):
        if request.url.path != "/healthz" and api_token:
            provided = request.headers.get("Authorization","")
            if not hmac.compare_digest(provided,f"Bearer {api_token}"):
                return JSONResponse(status_code=401,content={"error":{"code":"UNAUTHORIZED"}})
        if request.headers.get("content-length"):
            try: oversized = int(request.headers["content-length"])>1024*1024
            except ValueError: return JSONResponse(status_code=400,content={"error":{"code":"INVALID_REQUEST"}})
            if oversized: return JSONResponse(status_code=413,content={"error":{"code":"PAYLOAD_TOO_LARGE"}})
        return await call_next(request)

    async def read_json(request):
        chunks,size = [],0
        async for chunk in request.stream():
            size += len(chunk)
            if size>1024*1024: raise HarnessError("PAYLOAD_TOO_LARGE","request exceeds 1 MiB",status=413)
            chunks.append(chunk)
        data = b"".join(chunks)
        try: return json.loads(data)
        except (ValueError,UnicodeDecodeError) as exc: raise HarnessError("INVALID_JSON","request must contain valid JSON") from exc

    @api.get("/healthz")
    async def healthz():
        return {"status":"ok","mode":getattr(runtime,"mode","injected"),"handlers":[h.name for h in runtime.pipeline.handlers]}

    @api.get("/v1/audit/{audit_id}")
    async def audit(audit_id: str):
        value = await state.audit.get(audit_id)
        if value is None: raise HarnessError("AUDIT_NOT_FOUND","audit record not found",status=404)
        return value

    @api.get("/v1/sessions/{root_session_id}/trace")
    async def trace(root_session_id: str):
        return await build_trace(state.audit,root_session_id)

    @api.post("/v1/events/evaluate")
    async def evaluate(request: Request,idempotency_key: str | None = Header(default=None,alias="Idempotency-Key")):
        _,result = await runtime.submit(await read_json(request),idempotency_key)
        return result.to_dict()

    @api.post("/v1/approvals/{approval_id}/resolve")
    async def resolve(approval_id: str,request: Request):
        provided = request.headers.get("X-Approval-Token","")
        if not approval_token or not hmac.compare_digest(provided,approval_token):
            raise HarnessError("APPROVAL_UNAUTHORIZED","trusted confirmation channel required",status=403)
        body = await read_json(request)
        if not isinstance(body,dict) or set(body)!={"approved","actor"}:
            raise HarnessError("INVALID_APPROVAL","expected approved and actor")
        await state.audit.resolve_approval(approval_id,body["approved"],body["actor"])
        return {"approval_id":approval_id,"resolved":True}
    return api

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8080)
    parser.add_argument("--db",default="data/audit.db")
    parser.add_argument("--mode",choices=("observe","protect","stage1","stage2"),default="observe")
    parser.add_argument("--dataset-path")
    parser.add_argument("--rules-path")
    parser.add_argument("--policy-path")
    parser.add_argument("--indirect-detection", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_fastapi_app(args.db,mode=args.mode,dataset_path=args.dataset_path,
                rules_path=args.rules_path,policy_path=args.policy_path,indirect_detection=args.indirect_detection),host=args.host,port=args.port)

if __name__ == "__main__": main()
