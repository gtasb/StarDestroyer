"""Report rendering.

Large results go to disk; the transcript gets the first three plus a path and
a count. A 500-chain report must never be pasted into a conversation.
"""

import json
import pathlib

TOP_N = 3

_STATUS_LABEL = {
    "confirmed": "已确认",
    "needs_review": "待复核",
    "needs_dynamic": "需动态验证",
    "rejected": "已否证",
}


def _status(f: dict) -> str:
    return f.get("status") or (f.get("verdict") or {}).get("status", "?")


def _reason(f: dict) -> str:
    return f.get("reason") or (f.get("verdict") or {}).get("reason", "")


def _missing(f: dict):
    return f.get("missing") if "missing" in f else (f.get("verdict") or {}).get("missing")


def write(findings: list[dict], out_dir: str, title: str = "audit",
          gaps: list[str] | None = None) -> dict:
    d = pathlib.Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    # out_dir is unique per run; a second write (AI notes) replaces the first.
    jsonl = d / f"{title}.jsonl"
    md = d / f"{title}.md"

    with jsonl.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    md.write_text(render(findings, title, gaps), encoding="utf-8")
    return {"jsonl": str(jsonl), "markdown": str(md), "total": len(findings),
            "shown": min(TOP_N, len(findings))}


def _one(s) -> str:
    return " ".join(str(s).split())


_FIELDS = (("severity", "严重度"), ("cwe", "CWE"), ("auth", "鉴权（生产）"), ("auth_default", "鉴权（默认配置）"), ("cause", "根因"), ("impact", "影响"), ("conditions", "利用条件"), ("fix", "修复"))


def render(findings: list[dict], title: str, gaps: list[str] | None = None, top: int = TOP_N) -> str:
    """top=0 writes every finding out in full."""
    top = top or len(findings)
    lines = [f"# {title}", "", f"共 {len(findings)} 条" + (f"（本页展示前 {top} 条）" if top < len(findings) else ""), ""]
    if gaps:
        lines += ["> **本次扫描不完整，未报出不代表没有：**", ">"]
        lines += [f"> - {g}" for g in gaps] + [""]
    for f in findings[:top]:
        lines += [
            f"## {f.get('rule_id', '?')} — {_STATUS_LABEL.get(_status(f), _status(f))}",
            "",
            *([_one(f["message"]), ""] if f.get("message") else []),
            f"- 指纹：`{f.get('fingerprint', '-')}`",
            f"- 位置：`{f.get('file', '?')}:{f.get('line', '?')}`",
            f"- 证据级别：{f.get('evidence_level', '-')}",
            f"- 判定：{_reason(f)}",
        ]
        lines += [f"- {label}：{_one(f[k])}" for k, label in _FIELDS if f.get(k)]
        if f.get("review"):
            lines.append(f"- agent 复核：{f['review'].get('verdict')}，{_one(f['review'].get('reason', ''))}")
        if f.get("decision"):
            lines.append(f"- 人工结论：{f['decision']}")
        if _missing(f):
            lines.append(f"- 缺口：{_missing(f)}")
        trace = f.get("trace") or []
        if trace:
            lines.append("- 调用链：")
            for step in trace:
                lines.append(f"    - `{step.get('file')}:{step.get('line')}` "
                             f"[{step.get('kind')}] {step.get('text', '')}" + (f" — {_one(step['note'])}" if step.get("note") else ""))
        if f.get("ai_note"):
            lines += ["", "> " + f["ai_note"].replace("\n", "\n> ")]
        lines.append("")
    if len(findings) > top:
        lines += ["## 其余（仅位置）", ""]
        for f in findings[top:]:
            lines.append(f"- `{f.get('file')}:{f.get('line')}` {f.get('rule_id')} [{_status(f)}]")
    return "\n".join(lines)
