# Agent Security Harness Stage 2

这是一个面向 Agent Hook 的 Stage 2 字符串匹配验证产品。它在 Stage 1 架构上增加本地 CSV 数据集加载、规范化、恶意样本完整文本精确匹配、少量人工短语规则和 SQLite 审计闭环。

本阶段不是通用提示注入防御系统：`REVIEW` 只表示字符串规则命中、需要进一步研判，不证明存在攻击；未命中也不等于安全。Stage 2 不做工具/MCP/间接注入、模型分类器、正则/语义匹配或自动阻断。

## 运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
security-harness --host 127.0.0.1 --port 8080 --db data/audit.db
# Stage 2：数据集必须由有权限的使用者先下载到本地；程序不联网下载
security-harness --mode stage2 --dataset-path data/datasets/rogue-security/test.csv --rules-path data/synthetic/rules.json --db data/audit.db
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
python tools/evaluate_dataset.py data/synthetic/stage2.csv --rules data/synthetic/rules.json
Get-Content hook-input.json | python tools/claude_user_prompt_submit.py
```

## 约束与后续

- 输入模型默认拒绝未知顶层字段；扩展只能放在 `metadata` 和 `payload`。
- metadata 限制为 32 KiB、最多 6 层，并拒绝不可 JSON 序列化对象。
- SQLite 使用 WAL、外键和 busy timeout；审计默认只保存 payload 摘要和大小。
- `fail_open`/`fail_closed`/`fail_review` 仅用于运行时故障降级，不代表安全判定。
- 数据集来源为 `rogue-security/prompt-injections-benchmark`。使用者须自行接受 Hugging Face 条款并按 CC BY-NC 4.0 许可获取；原始数据、token、缓存和真实评估中间文件不得提交仓库。
- CSV 只接受 UTF-8/UTF-8-BOM，必须有 `text`/`label` 列；启动加载失败会直接报错，不会静默启用空规则集。
- 统一使用 `normalize-v1`：Unicode NFKC、casefold、连续空白折叠、首尾去空白；不移除标点、不翻译、不做同形字替换。
- Stage 2 通过 `HandlerProtocol` 注入 `PromptStringMatchHandler`，保留 Stage 1 的 Runtime/Pipeline/审计接口；幂等重放恢复原始风险信号。
- Claude UserPromptSubmit bridge 默认 monitor-only，只读取 stdin 的 `prompt` 并调用本地 API；输出合法空 Hook JSON，判定写入 stderr，不阻断提示词。
- 正式数据集未随仓库提供。没有授权文件时只能运行合成夹具，不能声称已完成真实数据集评估。
