# 测试流程与验证记录

日期：2026-10-02。环境：当前项目 Windows `.venv`，基础设施与合成夹具测试，不调用真实模型、不执行恶意命令。

## 自动测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

本次结果：39 passed。原有 10 项 Stage 1/2 测试保留，通过显式 Mock 注入避免生产默认模式使用测试控制字段。

| 验证类别 | 验证内容 |
|---|---|
| 持久化恢复 | 服务对象重建后序号继续、原任务与工具历史可读、旧数据库升级 |
| 幂等与失败 | 成功/降级结果重放、参数变化拒绝、取消事件恢复原审计记录 |
| 调度 | 并发自动分配连续序号、根会话隔离、锁注册表释放 |
| 多检测器 | REVIEW/BLOCK 优先级、一个检测器失败时保留其他检测器的决策、检测器输入隔离 |
| 来源与调用链 | 记忆来源区间、主/子 Agent 与 MCP 标识、父事件同根校验、DAG/时序输出 |
| 工具执行 | ALLOW 执行、BLOCK 不执行、REVIEW 确认后执行、重复调用不重复执行 |
| 确认限制 | 未确认、拒绝、过期、参数变化、上下文变化均拒绝执行 |
| 故障约束 | 观察模式未覆盖工具、检测降级时均不执行 |
| 结果采集 | ToolOutput 资源敏感标签进入后续上下文，来源与影响对象进入调用链 |
| HTTP | 实际 ASGI 路由、适配器认证、独立确认凭据、非法输入与请求大小限制 |
| Claude bridge | 启动真实本地 Uvicorn，连续运行两次桥接脚本，同一会话生成 seq 1/2，stdout 均为合法空 Hook JSON |

## 可运行演示

```powershell
.\.venv\Scripts\python.exe tools/demo_infrastructure.py
.\.venv\Scripts\python.exe tools/demo_infrastructure.py --trace-output outputs/demo_trace.json
```

预期：`TOOL_BLOCKED`；出现一次模拟用户确认；实际调用清单仅 `fs.read`、`net.fetch`；DAG 为 7 个节点、8 条边，最终 `pass: true`。所有工具均为内存夹具，不读写 SSH 文件、不发起网络请求。

## 原框架烟雾测试

```powershell
.\.venv\Scripts\python.exe tools/run_stage1_tests.py
.\.venv\Scripts\python.exe tools/mock_agent/cli.py --agents 8 --events-per-agent 20 --concurrency 16 --db data/mock-agent.db
```

本次独立 smoke：PASS。Mock Agent 使用 `--db :memory:` 验证 8 个 Agent、160 个事件，terminal_ratio 为 1.0。每次运行使用独立会话与幂等键，可重复运行。真实检测效果需使用独立攻防样本和完整适配器验证。

## 验收限制

这些结果证明本次基础设施的契约和执行行为，不证明五项赛题能力完整达标。尚未进行多语言/Unicode/多轮/语义伪装等鲁棒性评测，没有真实 MCP/子 Agent 端到端攻防场景，也未验证已知 CVE 防御。原 Stage 2 精确匹配测试继续通过，真实数据集的检测效果不属于本次新增基础设施的验收指标。
