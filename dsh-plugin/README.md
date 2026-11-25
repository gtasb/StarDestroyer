# dsh-stardestroyer

DeepSeek Harness (dsh) 包，把 StarDestroyer 的审计能力注册成原生工具。

## 它是什么

一个 **bundle**：`package.json` 里的 `dsh.bundle.patch` 指向 `cordis.patch.yml`，
后者插入一个 Cordis 插件行。插件（`index.js`）不重写审计逻辑，而是调用仓库根目录的
`cli.py`——引擎是 Python，边界是一个 JSON 进程调用。

## 安装

在本仓库根目录：

```bash
dsh plugin --profile <name> add ./dsh-plugin
dsh --profile <name>
```

链式安装会保留本目录自己的 `node_modules`；`@deepseek-ai/cordis` 与
`@deepseek-ai/dsh-tools` 同时声明在 `peerDependencies` 与 `devDependencies`，
与宿主共享实例。

## 工具

| 工具 | 作用 |
|---|---|
| `sd_scan` | 源码审计：画像 → 生成规则 → 污点分析 |
| `sd_review` | 取上次扫描待复核的发现，由你读码推翻 |
| `sd_review_verdict` | 回写复核结论，引用会被核对 |
| `sd_audit_next` / `sd_audit_submit` / `sd_audit_status` | 取审计单元自己审、提交（引用会被核对）、看进度 |
| `sd_code` | 代码导航：定义、调用者、实现、MyBatis 语句 |
| `sd_secrets` | 硬编码凭据，值打码 |
| `sd_jar_audit` | Java 字节码调用图，找 gadget 链 |
| `sd_sca` | 依赖树 → NVD 版本区间命中 |
| `sd_sca_triage` / `sd_sca_verdict` | 依赖 CVE 筛选与裁决 |
| `sd_logs` | 最近日志 |
| `sd_graph` | 资产图谱（技术/依赖/N-day/端点/功能） |
| `sd_kb_search` | 知识库检索，带出处 |
| `sd_web_search` | N-day 触达方式检索（Tavily） |

## 审计会话

控制台和 `audit_run` 起的是另一种会话，不需要安装本 bundle：`core/agents.py` 用 `--patch` 把 `audit.js` 插进
`headless` profile。它提供代码导航（`sd_symbol` `sd_callers` `sd_implementations` `sd_method` `sd_endpoints`
`sd_sinks` `sd_advisory`）和 `sd_submit`，并用 `ctx.tools.guard` 只放行被审项目内的 read / grep / glob；`AUDIT_ACCESS` 决定是否加上 shell（默认加）。
自由审计的会话另有 `sd_findings` `sd_opengrep` `sd_callgraph` `sd_deps`，可以派子 agent（`tool-subagent`，有上限）。
`catalog.mjs` 从已安装的 dsh 读出服务商与模型目录。

## 依赖

- 宿主：Node 侧由 dsh 提供 `@deepseek-ai/cordis`、`@deepseek-ai/dsh-tools`
- 引擎：Python 3.10+，`pip install -r ../requirements.txt`
- 可选环境变量：`DEEPSEEK_API_KEY`、`TAVILY_API_KEY`、`NVD_API_KEY`、
  `OPENGREP_BIN`、`TABBY_JAR`、`OPENSCA_BIN`
- 覆盖默认路径：`STARDESTROYER_CLI`（cli.py 的绝对路径）、
  `STARDESTROYER_PYTHON`（解释器）

## 状态

针对 dsh `developer preview` 编写；其插件 API 仍在快速迭代，升级后需回归验证。
