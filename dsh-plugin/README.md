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
| `sd_jar_audit` | Java 字节码调用图，找 gadget 链 |
| `sd_sca` | 依赖树 → NVD 版本区间命中 |
| `sd_graph` | 资产图谱（技术/依赖/N-day/端点/功能） |
| `sd_kb_search` | 知识库检索，带出处 |
| `sd_web_search` | N-day 触达方式检索（Tavily） |

## 依赖

- 宿主：Node 侧由 dsh 提供 `@deepseek-ai/cordis`、`@deepseek-ai/dsh-tools`
- 引擎：Python 3.10+，`pip install -r ../requirements.txt`
- 可选环境变量：`DEEPSEEK_API_KEY`、`TAVILY_API_KEY`、`NVD_API_KEY`、
  `OPENGREP_BIN`、`TABBY_JAR`、`OPENSCA_BIN`
- 覆盖默认路径：`STARDESTROYER_CLI`（cli.py 的绝对路径）、
  `STARDESTROYER_PYTHON`（解释器）

## 状态

针对 dsh `developer preview` 编写；其插件 API 仍在快速迭代，升级后需回归验证。
