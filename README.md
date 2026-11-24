# StarDestroyer

源码安全审计 agent。双引擎级联、按依赖自动生成规则、结果可复核；
Java / Python / Go 源码，Java 编译产物走调用图召回。

## 能力

| 层 | 做什么 |
|---|---|
| Opengrep 精度层 | 污点分析，输出带 kind 标注的完整调用链（source → through → sink） |
| Tabby 召回层 | Java 字节码建调用图，找无 source 的 gadget 链（`readObject → … → Runtime.exec`） |
| 规则自生成 | 读项目依赖 → 生成框架专属规则 → 引擎校验通过才启用 |
| SCA / N-day | OpenSCA 解依赖树 → NVD 按 CPE 版本区间判定是否真受影响 |
| 知识库 | 文档按需检索，带出处返回，**不注入提示词** |
| 资产图谱 | 应用 / 技术 / 版本 / 依赖 / N-day / 端点 / 功能 / 漏洞类别，节点带事实等级 |
| 复核 | 发现者不给自己判卷：独立复核调用只能降级或沿用，不能升级 |

## 架构

```
Web 控制台 / MCP 适配层（转发，无业务逻辑）
        │
   core/toolset.py   ← 工具注册表
        │
   pipeline / agent / rulegen / sca / asset_graph
        │
   Opengrep · Tabby(+Kùzu) · OpenSCA · NVD · Tavily · SQLite(KB)
```

资源按单次操作获取，不跨整个会话持有；超过 60 秒的命令外置为 job。

## 快速开始

```bash
pip install -r requirements.txt
python web/run.py          # http://127.0.0.1:8770
```

外部工具（放在项目内 `.work/` 下即可自动发现，也可用环境变量指定）：

| 工具 | 环境变量 | 默认位置 |
|---|---|---|
| Opengrep ≥ 2.0 | `OPENGREP_BIN` | `.work/og200/bin/opengrep` |
| Tabby v2 | `TABBY_JAR` | `.work/tabby/dist/tabby.jar` |
| OpenSCA CLI | `OPENSCA_BIN` | `.work/opensca/bin/opensca-cli` |

可选：

| 变量 | 作用 |
|---|---|
| `DEEPSEEK_API_KEY` | 复核与说明 |
| `TAVILY_API_KEY` | N-day 触达方式检索 |
| `NVD_API_KEY` | 提高 NVD 限流额度 |

MCP 接入：`python adapters/mcp_server.py`（stdio），共 18 个工具。

## 目录

```
core/          引擎、判定、规则生成、图谱、知识库（零 harness 依赖）
adapters/      MCP 适配层（18 行，只做转发）
web/           自托管控制台
demo/          验证用靶子（含刻意保留的漏洞，见下方声明）
tests/         并发、NVD 版本区间等离线用例
references/    sink 目录、复核规则、盲区登记
```

## 验证

```bash
python tests/nvd_ranges.py     # NVD 版本区间判定，离线
python tests/concurrency.py    # 资源池并发上限
```

对照靶子：`demo/java-gadget` 在 Opengrep 下 0 命中，Tabby 可报出完整链；
`demo/spring-proj` 的 `JdbcTemplate` 注入只有生成规则后才会命中。

## 已知限制

- Tabby 只支持 Java；Python / Go 走 Opengrep 单引擎。
- NVD 无 key 时限流 5 次/30 秒，依赖多的项目建图会慢。
- 端点功能是按路径关键词推断，不是语义理解。
- Kùzu 不支持 `tabby.algo.*` 存储过程，路径搜索用普通 Cypher 模板。

## 声明

`demo/` 下的代码**刻意包含漏洞**，仅用于验证检测能力；请勿用于生产。
本工具只应用于已获得书面授权的目标。
