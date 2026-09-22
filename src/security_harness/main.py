from __future__ import annotations
import argparse, asyncio, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    from fastapi import FastAPI, Header, HTTPException, Request
except ImportError:  # pragma: no cover - stdlib fallback remains available
    FastAPI = Header = HTTPException = Request = None
from .audit import AuditRepository
from .domain import HarnessError, SecurityEvent
from .runtime import Runtime
from .dataset_loader import DatasetLoadError, load_dataset
from .pipeline import Pipeline
from .prompt_matcher import PromptStringMatchHandler, load_phrase_rules

class App:
    def __init__(self, db: str, *, dataset_path: str | None = None, rules_path: str | None = None, mode: str = "stage1"):
        self.audit = AuditRepository(db)
        if mode == "stage2":
            if not dataset_path: raise DatasetLoadError("--dataset-path is required in stage2 mode")
            index = load_dataset(dataset_path); rules = load_phrase_rules(rules_path)
            handler = PromptStringMatchHandler(index.jailbreak, rules, dataset_sha256=index.report.file_sha256)
            self.runtime = Runtime(self.audit, pipeline=Pipeline(handler))
            self.dataset_report = index.report.to_dict()
        else:
            self.runtime = Runtime(self.audit); self.dataset_report = None

def create_fastapi_app(db: str, *, dataset_path: str | None = None, rules_path: str | None = None, mode: str = "stage1"):
    """Production entry point when declared FastAPI dependencies are installed."""
    app_state = App(db, dataset_path=dataset_path, rules_path=rules_path, mode=mode); api = FastAPI(title="Agent Security Harness", version="0.2.0")
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
    parser = argparse.ArgumentParser(); parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8080); parser.add_argument("--db", default="data/audit.db"); parser.add_argument("--mode", choices=("stage1", "stage2"), default="stage1"); parser.add_argument("--dataset-path"); parser.add_argument("--rules-path"); args = parser.parse_args()
    try:
        import uvicorn
        uvicorn.run(create_fastapi_app(args.db, dataset_path=args.dataset_path, rules_path=args.rules_path, mode=args.mode), host=args.host, port=args.port)
    except ImportError:
        Handler.app = App(args.db, dataset_path=args.dataset_path, rules_path=args.rules_path, mode=args.mode); server = ThreadingHTTPServer((args.host, args.port), Handler); print(f"Security Harness listening on http://{args.host}:{args.port}"); server.serve_forever()

if __name__ == "__main__": main()
