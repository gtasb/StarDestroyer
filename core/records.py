"""Finding records.

Borrowed from Cloudflare's security-audit-skill: a finding is a record, not
prose. The fingerprint is stable across waves -- it must not include line
numbers, or the same root cause re-files every time the file shifts.
"""

import hashlib
import pathlib

# confirmed      static chain complete (or a dynamic repro was recorded)
# needs_review   a path exists, controllability unproven
# needs_dynamic  chain crosses a library boundary
# rejected       hidden by a human decision; kept on disk, never removed
STATUSES = {"confirmed", "needs_review", "needs_dynamic", "rejected"}


_CAUSES = (("缺少授权或归属校验", (284, 285, 287, 306, 566, 639, 862, 863, 1220)), ("SQL 注入", (89, 564, 943)), ("命令执行", (77, 78)), ("代码或表达式注入", (94, 95, 917, 1336)),
           ("反序列化", (502,)), ("文件路径与上传", (22, 23, 73, 434)), ("SSRF", (918,)), ("XSS", (79, 80)), ("XXE", (611,)), ("凭据与密钥", (259, 321, 521, 522, 798)),
           ("签名、加密与重放", (294, 326, 327, 330, 345, 347, 352)), ("并发与状态", (362, 367, 372, 841)), ("资源消耗", (400, 770, 674, 1333)), ("信息泄露", (200, 203, 209, 532, 538)), ("日志与审计", (117, 223, 778)), ("异常与失败补偿", (459, 460, 703, 754, 755)), ("配置与默认值", (16, 276, 453, 1188)))
_BY_CWE = {f"CWE-{n}": label for label, ns in _CAUSES for n in ns}


def cause(rec: dict) -> str:
    """What has to be fixed, as a heading: one missing check shows up in many places."""
    if rec.get("rule_id") == "agent-dependency":
        return "有漏洞的依赖"
    return rec.get("cause") or _BY_CWE.get(rec.get("cwe") or "") or rec.get("cwe") or "其它"


def _rel(path: str, root: str) -> str:
    if root and pathlib.Path(root).is_file():
        root = str(pathlib.Path(root).parent)
    try:
        return pathlib.Path(path).resolve().relative_to(pathlib.Path(root).resolve()).as_posix()
    except ValueError:
        return pathlib.Path(path).as_posix()


def fingerprint(finding: dict, root: str) -> str:
    """Identity for reports and diffs. The whole trace is hashed: the sink text
    alone is often just a variable name and collides within one file."""
    rel = _rel(finding.get("file", ""), root)
    path = "\x1f".join(f"{s.get('kind', '')}:{s.get('text', '')}"
                       for s in finding.get("trace") or [])
    if not path:
        path = (finding.get("message") or "").strip()[:80]
    raw = f"{finding.get('rule_id', '')}|{rel}|{path}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def suppress_key(finding: dict, root: str) -> str:
    """Key under which a decision may hide this exact finding, and nothing else.

    It pins project, rule, every trace position and the content of every file on
    the trace: edit any of them and the finding is reviewed again. "" means the
    evidence could not be pinned, so it must never be suppressed.
    """
    steps = [(s.get("file", ""), s.get("line"), s.get("kind", ""), s.get("text", ""))
             for s in finding.get("trace") or []]
    files = sorted({f for f, *_ in steps} | {finding.get("file", "")})
    h = hashlib.sha256()
    h.update(repr((str(pathlib.Path(root).resolve()), finding.get("rule_id", ""),
                   finding.get("file", ""), finding.get("line"), steps)).encode())
    for f in files:
        try:
            h.update(hashlib.sha256(pathlib.Path(f).read_bytes()).digest())
        except OSError:
            return ""
    return h.hexdigest()[:32]


def make(finding: dict, verd: dict, root: str) -> dict:
    return {
        "fingerprint": fingerprint(finding, root),
        "suppress_key": suppress_key(finding, root),
        "rule_id": finding.get("rule_id", ""),
        "file": _rel(finding.get("file", ""), root),
        "line": finding.get("line"),
        "message": finding.get("message", ""),
        "status": verd.get("status"),
        "evidence_level": "static" if verd.get("status") == "confirmed" else "none",
        "reason": verd.get("reason", ""),
        "missing": verd.get("missing"),
        "severity": finding.get("severity", ""),
        "cwe": finding.get("cwe", ""),
        "trace": [{**s, "file": _rel(s["file"], root) if s.get("file") and root else s.get("file", "")}
                  for s in finding.get("trace") or []],
        "source_tool": verd.get("source", ""),
    }

