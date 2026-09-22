# Agent Security Harness Stage 1

这是一个面向 Agent Hook 的 Stage 1 架构最小验证产品。它验证事件接入、规范化、按会话有序执行、跨 Agent 并行、幂等、超时/取消、Mock Handler 和 SQLite 审计闭环。

Stage 1 不实现真实安全检测算法。`mock_rule` 只读取 `test.mock.*` 命名空间用于测试；真实提示词注入、数据泄露、危险操作等检测是 Stage 2 TODO。

## 运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
security-harness --host 127.0.0.1 --port 8080 --db data/audit.db
```

请求示例：

```powershell
curl.exe -X POST http://127.0.0.1:8080/v1/events/evaluate `
  -H "Content-Type: application/json" `
  -H "Idempotency-Key: cc-01-s-44-1" `
  -d '@tests/fixtures/event.json'
```

健康检查：`GET /healthz`；审计查询：`GET /v1/audit/{audit_id}`。

## 测试

```powershell
pytest -q
python tools/mock_agent/cli.py --agents 8 --events-per-agent 20 --concurrency 16
```

## 约束与后续

- 输入模型默认拒绝未知顶层字段；扩展只能放在 `metadata` 和 `payload`。
- metadata 限制为 32 KiB、最多 6 层，并拒绝不可 JSON 序列化对象。
- SQLite 使用 WAL、外键和 busy timeout；审计默认只保存 payload 摘要和大小。
- `fail_open`/`fail_closed`/`fail_review` 仅用于运行时故障降级，不代表安全判定。
- Stage 2 通过 `HandlerProtocol` 注入真实检测 Handler，不改变 Adapter、Runtime、Pipeline 和审计接口。

