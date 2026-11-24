---
name: stardestroyer
description: 对 Java/Python/Go 源码做污点审计；Java 编译产物走调用图召回；按依赖自动生成规则；带非注入式知识库。
---

# StarDestroyer

## 何时使用

需要审计一个源码目录或编译产物，要「漏洞在哪、参数从哪来、证据在哪」时。
有项目文档想沉淀成可检索知识时，用知识库。

## 工具

| 工具 | 作用 |
|---|---|
| `audit_scan(path, lang, ai, verify, auto)` | 污点扫描；`auto=True` 先按依赖生成规则 |
| `audit_jar(jar, mode, heap, limit)` | Tabby 调用图召回，找 gadget 链 |
| `project_profile(path)` | 语言 / 构建文件 / 依赖 / 框架 |
| `propose_rules(path, apply)` | 生成规则；`apply=True` 校验并落盘启用 |
| `list_generated_rules()` | 已生成规则与来源清单 |
| `kb_search(query, k)` | 检索知识库片段，带出处 |
| `rag_preview(query, k)` | 检索预览：命中片段与总字符数，显式不注入 |
| `sca_scan(path)` | 依赖树（含传递依赖）→ 版本命中的 CVE |
| `sca_triage(path, cvss_min, epss_pct_min)` | 确定性闸 + 把幸存项作为 `candidates` 交给 agent 核实 |
| `sca_record_verdicts(path, verdicts)` | 记录 agent 读码后的 keep/ignore，ignore 需证据 |
| `nvd_lookup(product, version)` | 单个产品的 NVD 查询 |
| `web_search(query)` | Tavily 检索，结果带 URL |
| `n_day_context(cve)` | 查这个 N-day 怎么被触达：gadget / sink / 路径 |
| `asset_graph_build(path)` | 建资产图谱 |
| `asset_graph_summary(db)` | 图谱统计、风险依赖、端点 |
| `kb_ingest(path)` / `kb_list()` | 入库 / 列出文档 |
| `submit_job` / `job_status` / `pool_stats` | 长任务与资源 |

Web 控制台：`python web/run.py` → http://127.0.0.1:8770

## 流水线

```
画像(依赖) → 生成规则 → 引擎校验 → Opengrep 污点扫描 → 去重已否证 → 独立复核 → 报告
                                    Tabby 调用图召回 ↗
```

产物在 `.work/scans/<时间戳>/`：`findings.json`、`ledger.json`、`findings.sarif`、`audit-*.md`。

## 规则生成（不是猜）

- 依据是项目**自己的构建文件与依赖**，提案里写明依据。
- 生成的规则先交给引擎解析校验，不通过就绝不启用。
- 规则按项目落盘到 `.work/rules/generated/`，附 manifest；下次只取适用的，不合并进全局。

## 知识库（非注入）

- 文档入库后**按需检索**，调用方拿到带出处的片段自行引用。
- 任何内容都不会被自动拼进提示词——这是知识库与提示词堆砌的分界。
- 中文按二元组切分索引，否则整段中文是一个不可检索的 token。

## 资产图谱

本体与事实等级取自 Burp-AI-Analyzer 的 `GraphTypes.java`
（`src/com/ai/analyzer/graph/`），节点：

`App / Technology / Version / Dependency / NDay / Endpoint / Feature / VulnClass / Finding / Evidence`

关系：`USES_TECHNOLOGY / HAS_VERSION / DEPENDS_ON / AFFECTED_BY / HAS_INTERFACE /
EXPOSES / COVERS / SUGGESTS / INDICATES`。

**事实等级**（每个节点都有 `status` + `confidence`）：

```
OBSERVED(5) > CONFIRMED(4) > DERIVED(3) > INFERRED(2) > REJECTED(1)
```

推进规则：只升不降；`REJECTED` 只能被 `OBSERVED` / `CONFIRMED` 覆盖。
当前赋值：SCA 依赖与 NVD 结果 = `OBSERVED`，端点正则 = `DERIVED`，
能力/漏洞类别推断 = `INFERRED`，引擎确认的发现 = `CONFIRMED`。

- 依赖来自 OpenSCA（含传递依赖），没有 OpenSCA 时退化为构建文件解析。
- N-day 走 NVD：CPE 字典解析 vendor → `virtualMatchString` 查 → CPE 版本区间判断。
- 端点从源码提取（Spring / Flask / Go），按路径词推断功能。

## 外部情报

- `web_search` 走 Tavily REST，已实测可用（需 `TAVILY_API_KEY`）。
- 该主机的 TLS 1.3 握手会被中间设备打断；`core/net.py` 对失败主机自动降到
  TLS 1.2 并记住选择。NVD / EPSS / Tavily 共用这一层。
- 结果只作为线索，带 URL 供引用，不直接改判定状态。

## SCA 一键筛选

三道闸，顺序固定：

1. **分数闸**（确定性）：CVSS ≥ 7.0 或 EPSS 百分位 ≥ 0.95 才保留。
2. **引用闸**（确定性）：源码里没有任何 import 引用该包 → 丢弃；
   但 `source_scanned=0`（没有源码可看）时不得以「未使用」为由丢弃。
3. **复核闸（harness agent，不是盲判）**：`sca_triage` 只产出 `candidates`，
   每条附带 `verify.steps`（grep 包名 → read 命中文件 → 对照 sinks 判断可达）。
   agent 用自己的 grep/read 工具读源码后，用 `sca_record_verdicts` 记录结论；
   ignore 必须带证据（file:line，或一次 grep 结果）。不把证据塞给模型让它凭摘要判断。

幸存依赖按 CWE 映射到 sink 清单，再在源码里定位调用点（提示，不是证明）。

## 硬规则

1. 调用链只能来自引擎输出（`dataflow_trace` / 图查询结果），禁止编造。
2. 「路径存在」≠「参数可控」；未复核的候选链一律 `needs_review`。
3. 反射 / 代理 / SPI / 二阶污点断边，登记 `references/blind-spots.md`，不得自行补边当事实。
4. 每条结论附：调用链 + 源码位置 + 证据来源工具名。
5. 大结果落盘，上下文只放前 3 条 + 路径 + 总数。
6. 超过 60 秒的命令走 `submit_job`。
7. **发现者不给自己判卷**：复核是独立调用，只能读证据，不能新增位置或抬高严重度。
8. `rejected` 按指纹落盘，后续轮次不得重复提交同一假设。

## 已验证的引擎行为（勿再猜）

- `--enable-interfile` 只对声明 `options: {interfile: true}` 的规则生效，否则静默零结果。
- trace 完整性按 `dataflow_trace` 的 `kind` 判定：需同时出现 `source` 与 `sink|sink_in_call`。
- Opengrep 2.0.0 能解析单实现与多实现的接口调用；它漏的是**无 source 的 gadget 链**。
- Tabby v2 构建阶段写 H2 内存库，CSV 导出是正式能力；配置在 `config/settings.properties`。
- Tabby 的 `.properties` 中 Windows 路径必须用正斜杠，反斜杠会被当作转义。
- mcp 2.x 的 `FastMCP` 已改名 `MCPServer`。
- NVD 的 `virtualMatchString` 用通配 vendor 会返回无关结果；必须先解析 vendor。
- NVD 的 `cpeName` 不接受通配版本（404）；`virtualMatchString` 才稳定。
- OpenSCA 只产 SBOM，不含漏洞库；漏洞映射由 NVD 完成。
