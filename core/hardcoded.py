"""Hardcoded credentials: gitleaks for tokens with a shape, our own rules for what has
none (passwords in configuration, literal crypto keys), an agent for what is real.

Values never leave this module in clear: records, reports and the agent's task carry
a mask, and `span` says where in the line it is. The audited project cannot turn the
scan off -- its .gitleaks.toml, .gitleaksignore and gitleaks:allow comments are not
honoured.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from . import ledger, logging, proc, profile, records, testcode, verdict

MAX_BYTES = 2_000_000
_CONFIG = {".yml", ".yaml", ".properties", ".ini", ".conf", ".cfg", ".toml", ".env", ".json", ".xml", ".sh", ".bat", ".ps1", ".gradle", ".tf", ".sql"}
_CODE = {".java", ".kt", ".groovy", ".scala", ".py", ".go", ".php", ".rb", ".cs"} | set(ledger.EXTENSIONS["js"])
_LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "cargo.lock", "composer.lock"}
_WORD = r"pass(?:word|wd|phrase)?|pwd|secret|access[-_.]?key|secret[-_.]?key|private[-_.]?key|api[-_.]?key|app[-_.]?key|encrypt(?:ion)?[-_.]?key|aes[-_.]?key|sign(?:ing)?[-_.]?key|token|credential"
# What such a key is called when it is about a credential rather than one.
_NOT_KEY = re.compile(r"(expir\w*|timeout|header|ur[li]|path|name|prefix|suffix|type|length|len|size|enabled?|polic\w*|encoder|field|params?|min|max|count|class|bean|mode|"
                      r"algorithm|alg|ttl|seconds?|minutes?|days?|retr\w+|strength|validity|issuer|endpoint|service|format|pattern|regex|column|label|placeholder|message|msg|"
                      r"error|hint|title|rule|required|visible|store|provider|location|file|id|ref|version|check|valid\w*|key[-_.]?id|num\w*)$", re.I)
_PLACEHOLDER = re.compile(r"^(?:\$\{.*|#\{.*|%[\w.]+%|\{\{.*|<.*|ENC\(.*|\*+|x{3,}|\.{3,}|-+|_+|true|false|null|none|nil|undefined|empty|required|string|optional|todo|n/?a|"
                          r"process\.env.*|os\.environ.*|System\.getenv.*|@\w+@|\$[A-Z_]+)$", re.I)
_DUMMY = re.compile(r"your|change[-_]?me|example|sample|placeholder|dummy|\bfoo\b|\bbar\b|replace|todo|fake|mock|test|xxxx", re.I)
_TEST = re.compile(r"(^|/)(src/)?tests?/|(^|/)(__tests__|e2e|fixtures?|mocks?|examples?|samples?|demo|docs?)/|\.(test|spec)\.\w+$|Test\.java$|_test\.(go|py)$", re.I)
# Texts shown to people, not settings.
_I18N = re.compile(r"(^|/)(messages?|i18n|lang|locales?)([-_.]\w+)*(/|\.properties$|\.json$|\.ya?ml$|\.[jt]s$)", re.I)
_SHIRO = {"kPH+bIxk5D2deZiIxcaaaA==", "4AvVhmFLUs0KTA3Kprsdag==", "2AvVhdsgUs0FSA3SDFAdag==", "3AvVhmFLUs0KTA3Kprsdag==", "Z3VucwAAAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g=="}


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.I)


# (rule, cwe, severity, what it is, where, pattern with a group v and maybe k)
RULES = [
    ("secret-config", "CWE-798", "high", "配置里的明文凭据", "config",
     _rx(rf"^\s*(?:-\s*|export\s+|set\s+|\$env:)?[\"']?(?P<k>[\w.\-\[\]]*(?:{_WORD})[\w.\-]*)[\"']?\s*[:=]\s*(?P<q>[\"']?)(?P<v>[^\s\"'#,;]+)(?P=q)")),
    ("secret-xml", "CWE-798", "high", "XML 里的明文凭据", "config",
     _rx(rf"\bname\s*=\s*\"(?P<k>[^\"]*(?:{_WORD})[^\"]*)\"\s+value\s*=\s*\"(?P<v>[^\"]+)\"")),
    ("secret-xml", "CWE-798", "high", "XML 里的明文凭据", "config", _rx(rf"<(?P<k>[\w.\-]*(?:{_WORD}))>\s*(?P<v>[^<\s]+)\s*</")),
    ("secret-xml", "CWE-798", "high", "XML 里的明文凭据", "config", _rx(rf"<[^>]*\s(?P<k>[\w.\-]*(?:{_WORD}))\s*=\s*\"(?P<v>[^\"]+)\"")),
    ("secret-url", "CWE-798", "high", "连接串里的明文口令", "any", _rx(r"\b[a-z][\w+.\-]*://[^\s:/@\"'<>]*:(?P<v>[^\s@\"'/<>]+)@[\w.\-]+")),
    ("secret-url", "CWE-798", "high", "连接串里的明文口令", "any", _rx(r"[?&;](?:password|pwd)=(?P<v>[^&;\s\"'<>]+)")),
    ("secret-code", "CWE-798", "high", "代码里的明文凭据", "code",
     _rx(rf"(?<![\w.\-])(?P<k>\w*(?:{_WORD})\w*)[\"']?\s*(?::\s*[\w<>\[\]. ]+?\s*)?(?::?=|:)\s*(?:new\s+String\(\s*)?(?P<q>[\"'`])(?P<v>[^\"'`\n]{{3,}})(?P=q)")),
    ("secret-code", "CWE-798", "high", "代码里的明文凭据", "code", _rx(r"getConnection\s*\([^;]*?,\s*\"[^\"]*\"\s*,\s*\"(?P<v>[^\"]+)\"\s*\)")),
    ("secret-code", "CWE-798", "high", "代码里的明文凭据", "code", _rx(r"\.(?:auth|setPassword|withPassword|password)\s*\(\s*[\"'](?P<v>[^\"'\s]+)[\"']\s*\)")),
    ("secret-crypto-key", "CWE-321", "high", "写死的加密或签名密钥", "code",
     _rx(r"\b(?:new\s+)?(?:SecretKeySpec|IvParameterSpec|DESKeySpec|DESedeKeySpec)\s*\(\s*(?:\w+\.\w+\(\s*)?\"(?P<v>[^\"]+)\"")),
    ("secret-crypto-key", "CWE-321", "high", "写死的加密或签名密钥", "code",
     _rx(r"\b(?:Keys\.hmacShaKeyFor|setSigningKey|signWith|verifyWith|Algorithm\.HMAC\w*|SecureUtil\.\w+|AES\.new|Fernet|HMACSHA\w+|hmac\.new|createHmac|setCipherKey)\s*\((?:[^()\"']*,\s*)?(?:\w+(?:\.\w+)*\(\s*)?b?[\"'](?P<v>[^\"'\s]{4,})[\"']")),
    ("secret-crypto-key", "CWE-321", "high", "写死的加密或签名密钥", "code",
     _rx(r"\bjwt\.(?:sign|verify|encode|decode)\s*\([^,\n]+,\s*[\"'](?P<v>[^\"'\s]{3,})[\"']")),
    ("secret-crypto-key", "CWE-321", "high", "写死的加密或签名密钥", "code",
     _rx(r"\b(?:createCipheriv|createDecipheriv|CryptoJS\.\w+\.(?:encrypt|decrypt)|Utf8\.parse)\s*\((?:[^,()\n]+,\s*)?[\"'](?P<v>[^\"'\s]{8,})[\"']")),
]


def binary() -> str:
    """gitleaks, or betterleaks, which takes the same arguments."""
    return os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks") or shutil.which("betterleaks") or ""


def mask(v: str) -> str:
    return (v[:2] if len(v) >= 8 else "") + f"***（{len(v)} 位）"


def _keep(key: str, value: str, where: str, quoted: bool) -> bool:
    if _PLACEHOLDER.match(value) or len(value) < 3:
        return False
    if key and _NOT_KEY.search(key):
        return False
    flat = re.sub(r"[^a-z0-9]", "", value.lower())
    if not flat:
        return False
    if where == "code":
        if re.search(r"[\s\u4e00-\u9fff]", value) or re.search(r"\$\{|%[sd]|\{\d*\}", value):
            return False  # prose or a template
        # A name of a credential is not one: PASSWORD = "password", "X-Access-Token", "sys:user:resetPwd"
        if not re.search(r"\d", value) and re.search(_WORD, value, re.I):
            return False
        if re.match(r"^[/.@#]|^https?://|^[a-z]+(?:[-_.:/][a-z]+)+$|^[A-Z][a-z]+(?:-[A-Z][a-z]+)+$", value):
            return False
        if flat == re.sub(r"[^a-z0-9]", "", key.lower()):
            return False
    else:
        if re.search(r"[\u4e00-\u9fff]", value):
            return False
        if re.fullmatch(r"\d+[smhd]?", value) and not re.search(r"pass|pwd|secret", key or "", re.I):
            return False  # token: 3600
        if not quoted and re.match(r"^[|>&*!\[{(]|^(?:https?|classpath|file):", value):
            return False
    return True


def _file(path: pathlib.Path, rel: str) -> list[dict]:
    ext = path.suffix.lower() or (".env" if path.name.startswith(".env") else "")
    if path.name.lower().startswith(".env"):
        ext = ".env"
    kinds = {"any"} | ({"config"} if ext in _CONFIG else set()) | ({"code"} if ext in _CODE else set())
    if len(kinds) == 1 or path.name.lower() in _LOCKS:
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n"), 1):
        if len(line) > 2000:
            continue
        for rid, cwe, sev, what, where, rx in RULES:
            if rid in ("secret-config", "secret-code") and _I18N.search(rel):
                continue
            if where not in kinds or (rid == "secret-xml") != (ext == ".xml") and where == "config":
                continue
            for m in rx.finditer(line):
                g, value, span = m.groupdict(), m.group("v"), list(m.span("v"))
                # ${NAME:default} is a credential whenever NAME is not set.
                if d := re.fullmatch(r"\$\{[^:{}]+:-?([^{}]+)\}", value):
                    value, span = d.group(1), [span[0] + d.start(1), span[0] + d.end(1)]
                if _keep(g.get("k") or "", value, where, bool(g.get("q"))):
                    out.append({"rule": rid, "cwe": cwe, "severity": sev, "what": what + ("（环境变量的默认值）" if d else ""), "key": g.get("k") or "", "value": value,
                                "file": rel, "line": n, "span": span, "engine": "rules"})
    return out


def own(root: pathlib.Path) -> tuple[list[dict], list[str]]:
    out, unread = [], []
    for f in (profile._walk(root) if root.is_dir() else [root]):
        try:
            if f.stat().st_size > MAX_BYTES or profile.BUILT.search(f.name) or (f.suffix.lower() in (".js", ".mjs", ".cjs") and ledger._minified(f)):
                continue
            out += _file(f, f.relative_to(root).as_posix() if root.is_dir() else f.name)
        except OSError:
            unread.append(f.name)
    return out, unread


# ---- gitleaks -------------------------------------------------------------------
_DEFAULT = 'title = "stardestroyer"\n[extend]\nuseDefault = true\n'


def _leaks(exe: str, target: str, work: pathlib.Path, timeout: int, rules: str = _DEFAULT) -> tuple[list[dict], list[str]]:
    conf, report = work / "conf.toml", work / "report.json"
    # Without -c the target's own .gitleaks.toml decides, and it can allow everything.
    conf.write_text(rules, encoding="utf-8")
    report.unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GITLEAKS_CONFIG")}
    r = proc.run([exe, "dir", target, "-c", str(conf), "-f", "json", "-r", str(report), "--no-banner", "--no-color", "--exit-code", "0",
                  "--ignore-gitleaks-allow", "-i", str(work / "none"), "--max-target-megabytes", "20"], timeout=timeout, cwd=str(work), env=env)
    if r.returncode or not report.exists():
        tail = [x for x in r.stderr.strip().splitlines() if x.strip()]
        why = re.search(r"error parsing regexp[^\n]*", r.stderr)
        raise RuntimeError(why.group(0)[:200] if why else (tail or ["没有输出"])[-1][:200])
    skipped = [x for x in r.stderr.splitlines() if "WRN" in x and "skipping" in x]
    return json.loads(report.read_text(encoding="utf-8") or "[]") or [], skipped


def _span(f: pathlib.Path, n: int, value: str) -> list[int]:
    line = f.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")[n - 1]
    at = line.find(value.split("\n")[0])
    return [at, at + len(value.split("\n")[0])] if at >= 0 else [0, len(line)]


def gitleaks(root: pathlib.Path, timeout: int = 900) -> tuple[list[dict], list[str]]:
    """(hits, gaps)."""
    exe = binary()
    if not exe:
        return [], ["没有找到 gitleaks，只跑了自建规则；云密钥、令牌、私钥等没有查"]
    gaps, base = [], root if root.is_dir() else root.parent
    with tempfile.TemporaryDirectory(prefix="sd-leaks-", ignore_cleanup_errors=True) as d:
        work = pathlib.Path(d)
        try:
            rows, skipped = _leaks(exe, str(root), work, timeout)
            # The target's .gitleaksignore hides what it names by full path. Scanned one by
            # one, those files have no such file beside them.
            named = set()
            try:
                for x in (base / ".gitleaksignore").read_text(encoding="utf-8", errors="replace").splitlines():
                    p = pathlib.Path(x.strip().rsplit(":", 2)[0])
                    if x.count(":") >= 2 and p.is_absolute() and p.is_file() and base in p.parents:
                        named.add(p)
            except (OSError, ValueError):
                pass
            for p in sorted(named)[:200]:
                rows += _leaks(exe, str(p), work, 60)[0]
            if len(named) > 200:
                gaps.append(f"项目的 .gitleaksignore 点名了 {len(named)} 个文件，只单独复扫了 200 个")
            if skipped:
                gaps.append(f"gitleaks 跳过了 {len(skipped)} 个路径：{skipped[0][-120:]}")
        except subprocess.TimeoutExpired:
            return [], [f"gitleaks 超时（{timeout}s），只有自建规则的结果"]
        except (OSError, RuntimeError, ValueError) as exc:
            return [], [f"gitleaks 没有跑成，只有自建规则的结果：{exc}"]
    out = []
    for x in rows:
        try:
            f = pathlib.Path(x["File"])
            rel = (f if f.is_absolute() else pathlib.Path.cwd() / f).resolve().relative_to(base.resolve())
            if set(rel.parts[:-1]) & profile.SKIP_DIRS - {"dist"}:
                continue
            value, n = str(x["Secret"]), int(x["StartLine"])
            span = _span(f, n, value)
        except (KeyError, ValueError, OSError, IndexError):
            gaps.append("有一条 gitleaks 结果无法定位")
            continue
        out.append({"rule": f"gitleaks-{x['RuleID']}", "cwe": "CWE-798", "severity": "high", "what": str(x.get("Description") or x["RuleID"])[:120],
                    "key": "", "value": value, "file": rel.as_posix(), "line": n, "span": span, "engine": "gitleaks"})
    return out, gaps


# ---- scan -----------------------------------------------------------------------
def _hide(text: str, values: list[str]) -> str:
    for v in sorted({x for x in values if x}, key=len, reverse=True):
        text = text.replace(v, mask(v))
    return text


_left: dict[str, int] = {}  # hits in test code, left out by the setting


def collect(path: str) -> tuple[list[dict], list[str]]:
    """Records with masked values, and what was not looked at."""
    root = pathlib.Path(path).resolve()
    base = root if root.is_dir() else root.parent
    proc.stage("硬编码扫描（gitleaks）")
    theirs, gaps = gitleaks(root)
    proc.stage("硬编码扫描（自建规则）")
    mine, unread = own(root)
    if unread:
        gaps.append(f"{len(unread)} 个文件读不了")
    from . import airules
    written, trouble = airules.secret_hits(root)
    gaps += trouble
    for h in written:
        try:
            mine.append({**{k: h[k] for k in ("rule", "cwe", "severity", "what", "key", "value", "line")}, "file": h["rel"], "span": _span(base / h["rel"], h["line"], h["value"]), "engine": "ai"})
        except (OSError, IndexError):
            gaps.append("有一条 AI 规则的结果无法定位")
    test = testcode.skip(root)
    _left[str(root)] = len({(h["file"], h["line"]) for h in theirs + mine if test(h["file"])})
    theirs, mine = [h for h in theirs if not test(h["file"])], [h for h in mine if not test(h["file"])]
    # One value on one line is one finding; gitleaks knows better what it is.
    hits: dict[tuple, dict] = {}
    for h in theirs + mine:
        same = next((k for k in hits if k[:2] == (h["file"], h["line"]) and (h["value"] in k[2] or k[2] in h["value"])), None)
        if same is None:
            hits[(h["file"], h["line"], h["value"])] = h
        elif not hits[same]["key"]:
            hits[same]["key"] = h["key"]
    places: dict[str, list] = {}
    for h in hits.values():
        places.setdefault(h["value"], []).append(f"{h['file']}:{h['line']}")
    by_line: dict[tuple, list] = {}
    for h in hits.values():
        by_line.setdefault((h["file"], h["line"]), []).append(h["value"])
    out = []
    for h in hits.values():
        line = (base / h["file"]).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")[h["line"] - 1]
        sev, note = h["severity"], ""
        if h["value"] in _SHIRO:
            sev, note = "critical", "，是公开的 Shiro 默认密钥"
        elif _DUMMY.search(h["value"]) or _TEST.search(h["file"]):
            sev, note = "low", "，像占位或测试值"
        f = {"rule_id": h["rule"], "message": f"{h['what']}{note}：{h['key'] + ' = ' if h['key'] else ''}{mask(h['value'])}", "file": str(base / h["file"]), "line": h["line"],
             "severity": sev, "cwe": h["cwe"], "trace": [{"kind": "sink", "file": str(base / h["file"]), "line": h["line"],
                                                          "text": _hide(line, by_line[(h["file"], h["line"])]).strip()[:200]}]}
        rec = records.make(f, {"status": verdict.NEEDS_REVIEW, "reason": "命中规则，真假和用途待判断", "missing": None, "source": "secrets"}, str(base))
        rec.update(span=h["span"], engine=h["engine"], also=[f"同一个值还在 {p}" for p in places[h["value"]] if p != f"{h['file']}:{h['line']}"][:20])
        out.append(rec)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda r: (order.get(r["severity"], 4), r["file"], r["line"]))
    logging.info("secrets", "scan done", path=str(root), gitleaks=len(theirs), rules=len(mine), findings=len(out))
    return out, gaps


def scan(path: str) -> dict:
    from . import decisions, pipeline, report, sarif
    root = pathlib.Path(path)
    if not root.exists():
        return {"ok": False, "error": f"路径不存在: {path}"}
    recs, gaps = collect(path)
    decisions.apply(recs)
    live = [r for r in recs if r["status"] != "rejected"]
    d = pipeline.new_scan_dir("secrets-")
    (d / "findings.json").write_text(json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
    out = report.write(live, str(d), title="secrets", gaps=gaps)
    out["sarif"] = sarif.write_sarif(live, str(d / "findings.sarif"), gaps)
    out["findings_json"] = str(d / "findings.json")
    return {"ok": True, "complete": not gaps, "incomplete_reasons": gaps, "engine": pathlib.Path(binary()).stem or "rules", "root": str(root.resolve()), "reportable": len(live),
            "by_engine": {e: sum(r["engine"] == e for r in recs) for e in ("gitleaks", "rules", "ai")}, "status_counts": pipeline._counts(recs),
            "severity_counts": pipeline._severities(live), "tests_skipped": _left.get(str(root.resolve()), 0), "top": live[:report.TOP_N], "artifacts": out}


# ---- what an agent may say about them ----------------------------------------------
def raw(rec: dict, root: pathlib.Path) -> str:
    """The value, read from the file again; "" when it is not there any more."""
    try:
        line = (root / rec["file"]).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")[rec["line"] - 1]
        return line[rec["span"][0]:rec["span"][1]]
    except (OSError, IndexError, KeyError):
        return ""


def scrub(value, recs: list[dict], root: pathlib.Path):
    """Nothing an agent hands in keeps a value: not in prose, not in a quoted line."""
    known = {(r["file"], r["line"]): raw(r, root) for r in recs}
    long = [v for v in known.values() if len(v) >= 6]

    def walk(x, at=None):
        if isinstance(x, dict):
            spot = (x.get("file"), x.get("line"))
            return {k: walk(v, spot) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v, at) for v in x]
        if isinstance(x, str):
            return _hide(x, long + ([known[at]] if known.get(at) else []))
        return x
    return walk(value)
