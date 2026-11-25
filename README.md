# StarDestroyer

源码安全审计 agent。审计由 agent 在完整源码上进行，引擎负责给线索；
Java / Kotlin / Python / Go / JavaScript / TypeScript / Vue / Svelte 源码，Java 编译产物走调用图召回。agent 跑在 DeepSeek Harness（dsh）上。

## 能力

| 层 | 做什么 |
|---|---|
| agent 审计 | 先读懂架构与鉴权，再逐个审接口、从 sink 反向追链、续追引擎断掉的链、验证每个 CVE 的漏洞 API 能否从外部到达 |
| 代码导航 | 定义、调用者、接口实现、MyBatis XML 语句与 `${}`，供 agent 沿调用链走到底 |
| Opengrep 精度层 | 污点分析，输出带 kind 标注的完整调用链（source → through → sink） |
| Tabby 召回层 | Java 字节码建调用图，找无 source 的 gadget 链（`readObject → … → Runtime.exec`） |
| 规则自生成 | 读项目依赖 → 生成框架专属规则 → 引擎校验通过才启用 |
| SCA / N-day | Maven 按父 POM / BOM 还原真实版本，其余由 OpenSCA 解依赖树 → OSV 按坐标批量查、它没答的再由 NVD 按 CPE 版本区间查 → 都没有结论的由 agent 查 |
| 硬编码 | gitleaks（云密钥、令牌、私钥）+ 自建规则（配置口令、写死的加密密钥）→ agent 判真假和用途；值一律打码 |
| SCA 筛选 | CVSS/EPSS 确定性闸 → 剩下的由 agent 追链，给出可触达 / 不可触达 |
| 知识库 | 文档按需检索，带出处返回，**不注入提示词** |
| 资产图谱 | 应用 / 技术 / 版本 / 依赖 / N-day / 端点 / 功能 / 漏洞类别，节点带事实等级 |
| 复核 | 每条发现由另一个独立 agent 会话读源码尝试推翻，引用逐条核对；推翻只降为待复核，排除由人决定 |
| 项目对话 | 随时就当前项目向 agent 提问：读源码、查发现、调引擎，流式回答，引用的文件位置可点开 |
| 断点续扫 | 停掉或重启控制台后从断开处继续：引擎按段、agent 按单元和会话 |
| 控制台 | 项目台账、后台任务（进度/取消/历史/继续）、发现复核、依赖、攻击面、调用链 |

## 架构

```
Web 控制台 / MCP 适配层（转发，无业务逻辑）
        │
   core/toolset.py   ← 工具注册表
        │
   audit（拆分工作单元、核对引用、断点续跑） ──→ agents ──→ dsh 会话
        │                                                    │ dsh-plugin/audit.js
   pipeline / rulegen / sca / asset_graph                    │（代码导航、提交、越界守卫）
        │                                                    │
   Opengrep · Tabby(+Kùzu) · OpenSCA · NVD · Tavily      codeintel
```

资源按单次操作获取，不跨整个会话持有；超过 60 秒的命令外置为 job。

## 快速开始

```bash
pip install -r requirements.txt
python web/run.py          # http://127.0.0.1:8770
```

审计 agent 需要 dsh：`npm install -g @deepseek-ai/dsh`，然后在控制台「设置」里选服务商、填 key。
没有 dsh 时引擎照常可用，但断链、接口、CVE 可达性都没有人看，结果会标为不完整。

外部工具（放在项目内 `.work/` 下即可自动发现，也可用环境变量指定）：

| 工具 | 环境变量 | 默认位置 |
|---|---|---|
| Opengrep ≥ 2.0 | `OPENGREP_BIN` | `.work/og200/bin/opengrep` |
| Tabby v2 | `TABBY_JAR` | `.work/tabby/dist/tabby.jar` |
| OpenSCA CLI | `OPENSCA_BIN` | `.work/opensca/bin/opensca-cli` |
| gitleaks（或 betterleaks） | `GITLEAKS_BIN` | 从 PATH 查找 |

可选：

| 变量 | 作用 |
|---|---|
| `LLM_PROVIDER` `LLM_MODEL` `LLM_BASE_URL` | agent 用的服务商与模型，默认 dsh 官方路由（`DEEPSEEK_API_KEY`） |
| `LLM_KEY_<服务商>` | 其它服务商的 key，如 `LLM_KEY_OPENAI` |
| `BUILD_JAVA_HOME` | 自动编译用的 JDK，默认系统的 |
| `AUDIT_ACCESS` | agent 会话权限：`shell`（默认）/ `readonly` / `open`，见下 |
| `AUDIT_CONCURRENCY` | 同时跑几个 agent 会话，默认 4 |
| `DSH_BIN` | dsh 路径，默认从 PATH 查找 |
| `TAVILY_API_KEY` | N-day 触达方式检索 |
| `NVD_API_KEY` | 提高 NVD 限流额度 |
| `SCA_OSV` | `0` 关闭 OSV（它会收到依赖的名字和版本） |
| `SCA_MAVEN` | 还原 POM 用的仓库，默认 Maven Central；可填镜像的 https 地址，`0` 关闭 |
| `POM_ROOTS` | 私有父 POM 在本机的目录，默认找项目旁边的仓库 |
| `AUDIT_INTERFILE_DEPTH` | 引擎跨文件追多深，默认 20 |
| `SCA_INDIRECT` | `0` 不扫间接依赖（依赖的依赖），默认扫；项目设置和单次扫描可另选 |

MCP 接入：`python adapters/mcp_server.py`（stdio），共 30 个工具。

命令行（JSON 入口，宿主集成用）：

```bash
python cli.py --list
python cli.py audit_scan --args '{"path": "demo/java", "auto": false}'
```

## 接入 DeepSeek Harness（dsh）

dsh 是「一切皆插件」的架构，所以二开的形态就是一个 bundle。仓库内
[`dsh-plugin/`](dsh-plugin/) 把 16 个审计工具注册成原生工具：

```bash
dsh plugin --profile <name> add ./dsh-plugin
dsh --profile <name>
```

插件不重写审计逻辑——它调用仓库根目录的 `cli.py`（一个 JSON 进程边界），
所以同一套引擎可以同时被 dsh、MCP 宿主和自带控制台复用。
详见 [dsh-plugin/README.md](dsh-plugin/README.md)。

## 目录

```
core/          引擎、判定、规则生成、图谱、知识库（零 harness 依赖）
adapters/      MCP 适配层（18 行，只做转发）
dsh-plugin/    DeepSeek Harness bundle（Cordis 插件）
web/           自托管控制台（server.py 接口，static/ 前端，无构建、无外部依赖）
cli.py         JSON 进程边界，供宿主调用
demo/          验证用靶子（含刻意保留的漏洞，见下方声明）
tests/         并发、NVD 版本区间等离线用例
references/    sink 目录、复核规则、盲区登记
```

## agent 审计

本项目不含 agent 运行时：循环、模型、服务商、上下文、重试都由 dsh 负责。这里做的是把审计拆成单元、
给 agent 代码导航和提交工具、把它限定在被审项目里，以及核对它说的每一句。

| 单元 | 内容 |
|---|---|
| 侦察 | 架构、鉴权、免登录路径、全局防护；后面每个单元都从这里出发 |
| 断链续追 | 引擎追到一半断掉的链，接着追到 sink，或给出断在哪里的证据 |
| 依赖 sink 追链 | 每个 CVE：漏洞 API 有没有用到、外部输入能不能到 |
| sink 反向追链 | 危险调用与 MyBatis `${}`，反向追到入口 |
| 接口审计 | 逐个接口给出鉴权情况、参数去向，以及越权等业务逻辑问题 |
| 复核 | 引擎已确认的发现和 agent 自己的新发现，都由另一个会话尝试推翻 |
| 补引擎缺口 | 引擎告警、没扫到的文件、没有结论的依赖、没解析全的依赖树，逐条由 agent 补上，补完缺口才关闭 |
| 硬编码判真伪 | 每个疑似凭据：是不是真的、谁能拿到、能打开什么 |
| 自由审计 | 以上都做完后再来一轮：AI 写规则再跑一遍引擎 → 规划覆盖面 → 多个审计员深读 → 覆盖复查员补漏 → 按新发现写变体规则再跑 |

自由审计用 [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)（MIT，见 `references/security-audit/`）的方法：
把项目按「攻击面 × 信任边界 × 攻击类」切块，每一类要么分给某一块、要么写明不适用，每块的每一类都要交覆盖记录。
**AI 写规则**：模仿已有规则的写法和本项目已确认的漏洞，为这个项目写三类规则，写完由程序再跑一轮引擎：

| 类型 | 写什么 | 怎么验证 |
|---|---|---|
| SAST | 项目自己封装的 source / sink / 净化函数，已确认漏洞的变体 | Opengrep 能加载、命中坏样例、不命中好样例、在项目里不超过 150 处 |
| 硬编码 | 项目特有的凭据写法 | 在 gitleaks（RE2，线性时间）里同样验证 |
| SCA | 认出没进依赖树的组件，给没有结论的依赖补产品名 | 必须在项目里找到；受不受影响由漏洞库判断，按猜的名字没查到不算「没有漏洞」 |

规则只属于这个项目，之后每次扫描都会带上，可以在「agent 审计」页停用。它们的命中只是线索，不会直接判为已确认，要再经 agent 追链和独立复核。

审计员可以派最多 4 个子 agent，可以自己动用引擎：现写 Opengrep 规则在全项目跑、查字节码调用图、查依赖与已有发现。
子 agent 受同一个守卫约束，不能再派子 agent，也不能提交结论。用量明显大于其它单元，可以单独勾掉。

- 每条链的每一跳都要有 `file:line + 原文`，程序逐条核对，对不上退回重做；漏答的接口、CVE、sink 也会退回。
- 同一个漏洞从多个入口报出时合并成一条。
- 单元按文件内容记录：中断后接着跑，改过的文件重新审，没改的不重复花钱。没审完的单元算缺口，不算「没有漏洞」。
- 会话权限有三档（设置页，或 `AUDIT_ACCESS`），都不读被审项目的 AGENTS.md / skill / `.env`：

  | 档位 | agent 能做什么 |
  |---|---|
  | `shell`（默认） | 读项目 + 跑命令，可主动调用 opengrep / gitleaks 等命令行工具；命令在 dsh 沙箱里，只能写空的临时工作区，环境里没有 API key |
  | `readonly` | 只读守卫：没有 shell 和联网，只能 read / grep / glob 项目内的文件（密钥类文件除外）和本项目的导航工具 |
  | `open` | 不设守卫，dsh 的全部工具可用，包括联网 |

  沙箱限制写，**不限制读**：`shell` / `open` 下，恶意源码若诱导成功，agent 能读到你的用户目录（含保存 key 的设置文件、`.ssh`），联网也不保证被拦。
  **审不可信来源的代码请用 `readonly`。** 提交的结论在会话外再核对一次，profile 里装的其它 `sd_*` 工具任何档位都不放行。
- 服务商来自已安装 dsh 的模型目录（DeepSeek、Anthropic、OpenAI、Google、OpenRouter 等四十多家），
  另加阿里云百炼、火山方舟、硅基流动、Ollama、LM Studio 和任意 OpenAI 兼容地址。设置页的「获取模型」向服务商的 `/models` 接口取最新列表；已存的 key 只发给它原来的地址。
- **审计会把相关源码发给所选服务商**；不想外发就用本机模型。token 用量在「agent 审计」页，先用少量单元试。
- 也可以由你自己的 agent 来审：MCP 用 `audit_next` / `audit_submit` / `code_navigate`，
  dsh 会话用 `sd_audit_next` / `sd_audit_submit` / `sd_code`，核对规则相同。

## 引擎没做完的，由 agent 补

引擎给出的每一条「不完整」都有人接，页面上写明由谁补、补到哪：

| 引擎的话 | 谁来补 |
|---|---|
| 跨文件分析到达深度上限 | sink 反向追链 + 断链续追，不受层数限制；全部做完才关闭 |
| 源文件没扫到 / 解析失败 | 逐个文件通读 |
| 依赖版本是推测的（父 POM 取不到） | 先由 agent 在工程里查清版本，再判它的 CVE |
| 依赖没有结论 | 先 OSV、再 NVD；仍没有的由 agent 从 pom / BOM / 锁文件 / lib 目录查版本、补产品名、判断是否进制品，再回漏洞库查 |
| 其它告警（引擎失败、依赖树没解析全……） | 按原话补查，找到的组件和漏洞照样入库 |

agent 查过仍不清楚的会如实留着，不会算成「没有漏洞」，也不会反复问。

## 硬编码

被审项目不能把扫描关掉：它的 `.gitleaks.toml`、`.gitleaksignore`、`gitleaks:allow` 注释都不生效。没有 gitleaks 时只跑自建规则，并列为缺口。
凭据的值不写进结果、报告和 agent 的任务里；但 **agent 判真伪时会读所在文件，值会随源码发给模型**，不想外发就在 agent 审计里勾掉「硬编码判真伪」。
git 历史不扫：在不可信的仓库里跑 `git log -p` 会执行它配置的外部程序。

## 自动编译（Java）

调用链（Tabby）需要字节码。在项目编辑里把「编译产物」设为自动编译，跑调用链前会先用本机的 Maven / Gradle 编译：

- 在 `.work/builds/` 的副本上编译，不动被审目录；源码没变就复用上次的产物；跳过测试。
- 有可执行 jar / war 就用它（含依赖）；只有普通模块 jar 时一起送进去，并标出「依赖不在图里」。
- 部分模块失败时用编译成功的继续，失败的列为缺口。
- **编译会执行项目自带的构建脚本和插件，等于在本机运行它的代码**，并联网下载依赖；环境里不带本项目的 API key，
  但这不是沙箱。默认关闭，只对信任的项目打开。

## 依赖版本怎么定

Maven 的版本由父 POM 链和导入的 BOM 决定，间接依赖也一样。父 POM 在私服时，只看工程会拿到别的库顺带声明的版本，
结果看着完整，其实是另一套版本。所以控制台自己还原，**不运行 Maven**（构建别人的工程等于运行它的代码）：

- POM 依次从工程内、`~/.m2`、项目旁边的仓库、Maven Central 取；自家 groupId 的不向外请求。
- 按就近原则、`dependencyManagement`、`exclusions`、`optional`、作用域算出每个模块的依赖树；测试依赖列出但不查。
- 取不到的父 POM / BOM / 构件写进缺口。由它们决定的版本标「推测」，先让 agent 查清版本，再判 CVE。

## 断点续扫

扫描状态写在 `.work/projects/<id>/` 下，取消、出错、重启控制台都不丢：

- 源码扫描按语言分段，大语言再按规则分段，每段跑完就存；依赖筛选存依赖树和 OSV 结果。
- 源码、规则、引擎或语言选择变了，旧的分段作废重来；扫完一次后断点清除，下次是完整的一遍。
- agent 审计按单元存结果：会话一结束就落盘，归档和复核在后面；模型回复损坏时在原会话里接着要，不整单重来。
- 审到一半被停的单元，24 小时内同一模型、同一权限下接着原来的 dsh 会话。
- 硬编码、攻击面、调用链不分段，继续就是重跑这一项。

重启后任务显示为「被打断」，概览和任务页可以一键继续。扫描对话框里的「从头开始」会丢掉断点。

## 项目对话

项目页的「对话」和「agent 审计」用同一套工具、守卫和会话权限，agent 仍由 dsh 运行（每个项目一个
`dsh --profile acp` 进程，首次约 10 秒，闲置 15 分钟关闭）。

- 首条消息会带上技术画像、侦察结论和已有发现的摘要；发现详情里的「问 agent」会带上那条发现。
- 可以换模型和推理强度、中途停止、继续、重新回答；复杂问题 agent 会分给子 agent。
- 对话存在 `.work/projects/<id>/chats/`，刷新、重启后接着原来的会话。删除项目会一并删除。
- 问答只读：不改源码、不改发现的状态。**读到的源码片段会发给所选的模型服务商**，和审计一样。

## 控制台的访问限制

控制台只监听 127.0.0.1，并校验 Host、Origin 和每次启动随机生成的令牌（由页面自动携带）。
重启后旧页面需要刷新。脚本请用 `cli.py`，不要直接调 `/api/`。
这些校验挡的是浏览器里的恶意网页，挡不住本机上已经在运行的程序。

## 验证

```bash
python tests/no_silent_misses.py  # 失败/不完整/被压制都不得显示成「干净」，离线，需 Opengrep
python tests/console_security.py  # 控制台访问限制、命令注入、路径越界，离线
python tests/agent_audit.py       # agent：代码导航、越界守卫、引用核对、断链续追、CVE 追链、复核、续跑，离线
python tests/regressions.py       # 修过的缺陷：版本比较、并发写、任务、知识库、端点等
python tests/rules.py             # 每条规则必须命中漏洞样例、不误报安全样例
python tests/secrets_scan.py      # 硬编码：命中、打码、关不掉、判真伪，离线，需 gitleaks
python tests/maven.py             # 父 POM / BOM 还原、推测版本、跨文件深度，离线
python tests/audit_flow.py        # 审计的调度、落盘、重试、合并复核、根因分组，离线
python tests/resume.py            # 断点续扫、任务继续、间接依赖开关，离线
python tests/chat.py              # 项目对话：流式、停止、重启、续接、守卫，离线
python tests/engine_gaps.py       # 引擎缺口由谁补、补完才关，OSV / NVD 回退，离线
python tests/languages.py         # JS / TS / Vue 全链路，Java 自动编译
python tests/nvd_ranges.py     # NVD 版本区间判定，离线
python tests/concurrency.py    # 资源池并发上限
```

对照靶子：`demo/java-gadget` 在 Opengrep 下 0 命中，Tabby 可报出完整链；
`demo/spring-proj` 的 `JdbcTemplate` 注入只有生成规则后才会命中。

## 已知限制

- NVD 按产品名匹配，`spring-*` 等子模块按整个产品算，会偏多；OSV 按坐标匹配，较准。没有坐标的组件只能走 NVD。
- Tabby 只支持 Java；其它语言走 Opengrep 单引擎。
- Vue / Svelte 的 `<script>` 抽出来扫，组件之间、组件与 `.ts` 之间的跨文件引擎追不了，由 agent 追；模板里的 `v-html` 等作为线索。
- 前端的 `node_modules`、构建产物、压缩文件、类型声明不审，数量显示在覆盖率里。
- NVD 无 key 时限流 5 次/30 秒，依赖多的项目建图会慢。
- 端点的功能标签按路径关键词推断，只用来排先后；结论以 agent 审计为准。
- 代码导航是词法级的，不解析重载和泛型；agent 读源码补足。
- Kùzu 不支持 `tabby.algo.*` 存储过程，路径搜索用普通 Cypher 模板。

## 声明

`demo/` 下的代码**刻意包含漏洞**，仅用于验证检测能力；请勿用于生产。
本工具只应用于已获得书面授权的目标。
