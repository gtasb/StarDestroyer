# Sink 目录

按语言维护。每条给出：入口 → 汇聚点 → 需要的净化。规则文件在 `core/templates/opengrep/`，
本文件只解释「为什么这些是 sink」，不复制规则。

## Java

| 类别 | 入口 | Sink | 净化 |
|---|---|---|---|
| SQLi | `getParameter` / `@RequestParam` | `Statement.execute*` | `prepareStatement` + 绑定参数 |
| 命令注入 | 同上 | `Runtime.exec` / `ProcessBuilder.command` | 白名单 / 参数数组 |
| SpEL/OGNL | 同上 | `SpelExpressionParser.parseExpression` | 不允许用户控制表达式；用模板 |
| SSRF | 同上 | `URL.openConnection` / `RestTemplate.exchange` | 目标域名白名单 |
| 反序列化 | `getInputStream` | `ObjectInputStream.readObject` | `ObjectInputFilter` 白名单类 |
| 路径穿越 | 同上 | `new File(base, name)` | `normalize()` 后校验前缀 |
| XSS | 同上 | 直接拼接进响应 | 模板引擎默认转义 |

## Python

| 类别 | 入口 | Sink | 净化 |
|---|---|---|---|
| SQLi | `request.args/form/GET/POST` | `cursor.execute` | 参数化占位符 |
| 命令注入 | 同上 | `os.system` / `subprocess.*` | `shell=False` + 参数列表 |
| 反序列化 | `request.data` | `pickle.loads` / `yaml.load` | `yaml.safe_load`；禁 pickle |
| SSRF | 同上 | `requests.*` / `urlopen` | 目标校验 + 禁内网段 |
| SSTI | 同上 | `render_template_string` | 不渲染用户模板 |

## Go

| 类别 | 入口 | Sink | 净化 |
|---|---|---|---|
| SQLi | `r.URL.Query().Get` / `r.FormValue` | `db.Query/Exec` | 占位符 `$1` + 参数 |
| 命令注入 | 同上 | `exec.Command` | 参数分离，禁 `sh -c` 拼接 |
| SSRF | 同上 | `http.Get/Post` | 目标校验 |
| 路径穿越 | 同上 | `os.Open(filepath.Join(...))` | `filepath.Clean` + 前缀校验 |

## 不在本表内的

未列入的 sink 不是「安全」，而是「尚未建模」。新增时同时补规则与本文，二者缺一不可。
