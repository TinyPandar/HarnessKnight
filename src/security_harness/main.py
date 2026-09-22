from __future__ import annotations
import argparse, asyncio, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .audit import AuditRepository
from .domain import HarnessError, SecurityEvent
from .runtime import Runtime

class App:
    def __init__(self, db: str): self.audit = AuditRepository(db); self.runtime = Runtime(self.audit)

def create_fastapi_app(db: str):
    """Production entry point when declared FastAPI dependencies are installed."""
    from fastapi import FastAPI, Header, HTTPException, Request
    app_state = App(db); api = FastAPI(title="Agent Security Harness Stage 1", version="0.1.0")
    @api.get("/healthz")
    async def healthz(): return {"status": "ok", "stage": "1"}
    @api.get("/v1/audit/{audit_id}")
    async def audit(audit_id: str):
        value = await app_state.audit.get(audit_id)
        if value is None: raise HTTPException(404, detail={"code": "AUDIT_NOT_FOUND"})
        return value
    @api.post("/v1/events/evaluate")
    async def evaluate(request: Request, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        try:
            raw = await request.json(); event = SecurityEvent.from_dict(raw, idempotency_key); return (await app_state.runtime.evaluate(event)).to_dict()
        except HarnessError as exc: raise HTTPException(exc.status, detail={"code": exc.code, "message": exc.message, "retryable": exc.retryable, "details": exc.details}) from exc
    return api

class Handler(BaseHTTPRequestHandler):
    app: App
    def _send(self, status, body):
        data = json.dumps(body, ensure_ascii=False, default=str).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path == "/healthz": return self._send(200, {"status": "ok", "stage": "1"})
        if self.path.startswith("/v1/audit/"):
            item = asyncio.run(self.app.audit.get(self.path.rsplit("/",1)[-1])); return self._send(200, item) if item else self._send(404, {"error": {"code": "AUDIT_NOT_FOUND"}})
        self._send(404, {"error": {"code": "NOT_FOUND"}})
    def do_POST(self):
        if self.path != "/v1/events/evaluate": return self._send(404, {"error": {"code": "NOT_FOUND"}})
        try:
            length = int(self.headers.get("Content-Length", "0"));
            if length > 1024*1024: raise HarnessError("PAYLOAD_TOO_LARGE", "request exceeds 1 MiB", status=413)
            raw = json.loads(self.rfile.read(length)); event = SecurityEvent.from_dict(raw, self.headers.get("Idempotency-Key")); result = asyncio.run(self.app.runtime.evaluate(event)); self._send(200, result.to_dict())
        except HarnessError as exc: self._send(exc.status, {"error": {"code": exc.code, "message": exc.message, "retryable": exc.retryable, "details": exc.details}})
        except Exception as exc: self._send(500, {"error": {"code": "INTERNAL_ERROR", "message": str(exc)}})
    def log_message(self, *_): pass

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8080); parser.add_argument("--db", default="data/audit.db"); args = parser.parse_args()
    try:
        import uvicorn
        uvicorn.run(create_fastapi_app(args.db), host=args.host, port=args.port)
    except ImportError:
        Handler.app = App(args.db); server = ThreadingHTTPServer((args.host, args.port), Handler); print(f"Security Harness Stage 1 listening on http://{args.host}:{args.port}"); server.serve_forever()

if __name__ == "__main__": main()
