# HarnessKnight

面向大模型智能体提示注入与工具滥用的安全框架基础设施，对齐“华为杯”第五届中国研究生网络安全创新大赛揭榜挑战赛题目 5。

当前提供：统一事件与来源区间、持久化任务/计划/工具历史、多检测器组合、JSON 工具策略 DSL、SDK 工具执行网关、调用绑定确认、SQLite 审计、跨 Agent/MCP 调用关系及 Mermaid DAG/时序图输出。

这是框架基础设施阶段。多源语义检测、意图偏离算法、敏感数据流跟踪、全部工具策略、抗绕过算法及真实 MCP/宿主工具拦截仍需实现；现有字符串匹配不代表通用攻击检测能力。

## 安装与运行

建议使用 Windows/Linux、Python 3.12+、单进程部署。本仓库没有模型推理服务，因此基础设施本身不需要 GPU；后续语义检测器的硬件需求另行评估。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'

# 观察模式：默认不加载数据集，也不启用 MockRuleHandler。
.\.venv\Scripts\python.exe -m security_harness --mode observe --db data/audit.db

# 策略模式：演示策略仅用于验证 DSL 与执行闭环，不是完整安全策略集。
.\.venv\Scripts\python.exe -m security_harness --mode protect --policy-path examples/policies/demo.json --db data/policy.db

# Stage 2：本地提示词字符串匹配，CSV 必须由有权限的使用者自行准备。
.\.venv\Scripts\python.exe -m security_harness --mode stage2 --dataset-path data/datasets/rogue-security/prompt-injections-benchmark/prompt-injections-benchmark.csv --rules-path data/synthetic/rules.json
```

`stage1` 是显式 Mock 测试模式，会读取 `metadata["test.mock"]`，不能作为生产检测器。`protect` 未配置策略时启动失败；数据加载、规则校验在创建数据库之前完成。

服务默认只监听 `127.0.0.1:8080`，运行一个进程/worker。可通过宿主的环境配置设置 `HARNESS_API_TOKEN` 和单独的 `HARNESS_APPROVAL_TOKEN`。前者用于适配器请求的 Bearer 认证；后者仅交给可信用户确认通道，不能提供给模型或工具。代码不自动加载 `.env`；真实凭据只保存在被忽略的本地配置中。

## 接口与 SDK

| 接口 | 作用 |
|---|---|
| `GET /healthz` | 实际模式、检测器名称 |
| `POST /v1/events/evaluate` | 事件研判；可省略 `seq`，由服务在锁内分配 |
| `GET /v1/audit/{audit_id}` | 判定、执行记录、来源信息、摘要证据 |
| `GET /v1/sessions/{root_session_id}/trace` | DAG 数据、时间线、Mermaid DAG 与时序图源码 |
| `POST /v1/approvals/{approval_id}/resolve` | 可信用户确认，要求额外 `X-Approval-Token` |

单 Agent 默认根会话标识为 `agent_id:session_id`，跨 Agent 协作必须由可信适配器统一设置 `trace.root_session_id`。`causal_event_id` 必须引用同一根会话中已经记录的事件。

HTTP evaluate 接口只返回决策。真正执行拦截由 `ToolGateway(runtime, registered_tools)` 完成：仅注册工具可执行，`BLOCK` 拒绝，`REVIEW` 等待确认，`ALLOW` 放行；检测故障或全部检测器跳过时暂停执行。确认与事件指纹绑定、默认 300 秒有效且只能消费一次。确认期间上下文变化时必须提交新的调用重新研判。

工具需注册为 `async callable(arguments)`。返回 `ToolOutput` 可附带资源敏感标签、来源区间及影响对象，供下一次研判和调用链查询使用。网关会生成 `tool.call.after/error`，已领取执行的事件不会自动再次执行；崩溃后尚未完成的执行需要人工核查。

Claude UserPromptSubmit bridge 仍是 **monitor-only**。工具执行可通过下面的 PreToolUse hook 接入网关。

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tools/demo_infrastructure.py
.\.venv\Scripts\python.exe tools/run_stage1_tests.py
.\.venv\Scripts\python.exe tools/mock_agent/cli.py --agents 8 --events-per-agent 20 --concurrency 16 --db data/mock-agent.db
```

演示工具全部是内存夹具，不操作真实文件或网络。它验证 README 读取放行、SSH 目录写入阻断、网络调用确认后放行，并输出调用链统计。

- [整体设计与扩展接口](docs/FRAMEWORK_DESIGN.md)
- [测试流程与本次验证记录](docs/VALIDATION.md)

审计默认只持久化 payload 摘要；上下文保留经过尽力脱敏和大小限制的任务文本与工具参数。来源 token 区间由适配器提供，本框架不自行推断 tokenizer。完整原始证据存储、访问权限、保留周期和追溯 UI 尚未实现。

Stage 2 数据来源为 `rogue-security/prompt-injections-benchmark`，获取者须遵守 Hugging Face 访问条款及 CC BY-NC 4.0。数据集、凭据与真实运行数据均不提交仓库。

## AgentGuard-derived injection detection

The `security_harness.agentguard` package adapts bounded advisory detection modules derived from AgentGuard; see [NOTICE](NOTICE). Indirect detection is on by default; disable it with `--no-indirect-detection` or `HarnessConfig(indirect_detection=False)`. User prompts are recorded only and stay ALLOW; tool and resource content can receive REVIEW. Document extraction keeps `pypdf` and `python-docx` optional; install them with `pip install .[docs]` to enable PDF and DOCX parsing.

## Claude Code PreToolUse hook

Start the harness in protect mode:

```sh
python3 -m security_harness --mode protect --policy-path examples/policies/claude_default.json
```

The hook maps harness decisions as follows:

| Harness decision | Claude Code permission |
| --- | --- |
| ALLOW | allow |
| REVIEW | ask |
| BLOCK | deny |
| unavailable, timeout, or degraded | deny by default |
| `HARNESS_HOOK_FAIL_MODE=open` | no decision; use Claude Code's normal permission flow |

Add this to `~/.claude/settings.json` (replace the script path with its absolute path):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "python3",
            "args": ["/ABSOLUTE/PATH/HarnessKnight/tools/claude_pre_tool_use.py", "--timeout", "3"],
            "timeout": 10,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Known limitations:

- Variable, alias, and function indirection and scripts (`./x.sh`, `make`, git hooks, `python script.py`) are not inspected.
- Only listed network tools are recognised; Python/requests, SSH config `ProxyCommand`, DNS, and similar traffic may be missed.
- `$(...)`, heredocs, and inline `-c` code force REVIEW.
- Every `WebFetch` asks for approval.
- Writes into any `.git` directory are sensitive and BLOCKed.
- Reads of credential files are ALLOW; only writes are blocked.
- Glob, Grep, WebSearch, and MCP tools produce no impacts and are ALLOW.

## PostToolUse (M2)

Register both hooks in `~/.claude/settings.json`; use an absolute path to each script:

```json
{
  "hooks": {
    "PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"python3","args":["/ABSOLUTE/PATH/HarnessKnight/tools/claude_pre_tool_use.py"],"timeout":10,"onFailure":"block"}]}],
    "PostToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"python3","args":["/ABSOLUTE/PATH/HarnessKnight/tools/claude_post_tool_use.py"],"timeout":10,"onFailure":"block"}]}]
  }
}
```

Both scripts read `HARNESS_URL` (default `http://127.0.0.1:8080/v1/events/evaluate`), optional `HARNESS_API_TOKEN`, and `HARNESS_HOOK_FAIL_MODE` (`closed` by default; `open` passes through on scan failures). PostToolUse returns `{}` for a clean ALLOW. A flagged result returns `decision: block` with factual context; Claude still sees the original tool output. This reports the result and informs subsequent reasoning; it cannot reverse the completed operation.

Indirect injection taints the root session permanently. Later network egress, git push, credential access, unparsed actions, unanalyzed Bash, and writes outside `cwd` require approval (`ask`). Existing policy BLOCK decisions remain BLOCK. Inspect the chain at `GET /v1/sessions/claude-code:SESSION_ID/trace` (URL-encode the root id); nodes include `risk_codes` and edges include `causal` and `taint`.

The event content fingerprint excludes `event_id` and `occurred_at`, so retries with fresh delivery identifiers replay the original event and decision.

Known limitations:

- PostToolUse runs after the tool already executed and cannot undo writes or network calls; protection comes from blocking later high-risk actions.
- Detection is heuristic and can produce false positives or false negatives. Taint applies to the root session and is never cleared.
- The Claude adapter scans at most 200,000 characters; truncated results raise a scan-limit signal and taint the session conservatively. Payloads over 1 MiB fail the server scan and the hook fails closed with a block reason; that failure does not create server-side taint. Taint is triggered only by detector signals.
- Only text in `tool_response` is scanned; images are not. PDF/DOCX extraction requires the `[docs]` extra and reads the file from disk.
- If PreToolUse is not registered, the causal link is omitted after the server reports an unknown parent.
- Old audit database rows created before the fingerprint change will not replay across the change.

Offline evaluation commands (from the repository root):

```sh
python eval/agentguard/run_bypass_matrix.py
python eval/agentguard/run_public_injection.py
```
