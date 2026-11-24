"""Report rendering.

Large results go to disk; the transcript gets the first three plus a path and
a count. A 500-chain report must never be pasted into a conversation.
"""

import json
import pathlib
import time

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


def write(findings: list[dict], out_dir: str, title: str = "audit") -> dict:
    d = pathlib.Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    jsonl = d / f"{title}-{stamp}.jsonl"
    md = d / f"{title}-{stamp}.md"

    with jsonl.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    md.write_text(render(findings, title), encoding="utf-8")
    return {"jsonl": str(jsonl), "markdown": str(md), "total": len(findings),
            "shown": min(TOP_N, len(findings))}


def render(findings: list[dict], title: str) -> str:
    lines = [f"# {title}", "", f"共 {len(findings)} 条（本页展示前 {min(TOP_N, len(findings))} 条）", ""]
    for f in findings[:TOP_N]:
        lines += [
            f"## {f.get('rule_id', '?')} — {_STATUS_LABEL.get(_status(f), _status(f))}",
            "",
            f"- 指纹：`{f.get('fingerprint', '-')}`",
            f"- 位置：`{f.get('file', '?')}:{f.get('line', '?')}`",
            f"- 证据级别：{f.get('evidence_level', '-')}",
            f"- 判定：{_reason(f)}",
        ]
        if _missing(f):
            lines.append(f"- 缺口：{_missing(f)}")
        trace = f.get("trace") or []
        if trace:
            lines.append("- 调用链：")
            for step in trace:
                lines.append(f"    - `{step.get('file')}:{step.get('line')}` "
                             f"[{step.get('kind')}] {step.get('text', '')}")
        if f.get("ai_note"):
            lines += ["", "> " + f["ai_note"].replace("\n", "\n> ")]
        lines.append("")
    if len(findings) > TOP_N:
        lines += ["## 其余（仅位置）", ""]
        for f in findings[TOP_N:]:
            lines.append(f"- `{f.get('file')}:{f.get('line')}` {f.get('rule_id')} [{_status(f)}]")
    return "\n".join(lines)
