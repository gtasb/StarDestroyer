"""Verification agent.

Borrowed from cloudflare/security-audit-skill: the agent that found a hit does
not grade it. This module runs a second, independent call whose only job is to
falsify the finding from the evidence alone. It cannot add locations and it
cannot raise severity; it may only accept or reject.

A rejection is persisted by fingerprint so a later wave cannot resubmit the
same hypothesis.
"""

import json
import os
import pathlib

from . import llm

REJECTED_FILE = pathlib.Path(
    os.environ.get("AUDIT_REJECTED_FILE",
                   pathlib.Path(__file__).resolve().parents[1] / ".work" / "rejected.json")
)

SYSTEM = (
    "你是独立复核者，任务是**否定**给定发现。只依据提供的证据判断，禁止补充证据中没有的位置。\n"
    "只输出一个 JSON 对象，不要任何外层文字或代码块：\n"
    '{"verdict":"accept|reject","reason":"<=80字","checked":["检查过的点"]}\n'
    "reject 的条件：证据自相矛盾、路径无法从入口到达汇聚点、参数明显来自常量/配置、或命中在测试/死代码。\n"
    "证据不足不等于 reject —— 不足以支撑 reject 时输出 accept，并在 reason 写「证据不足」。"
)


def _parse(raw: str) -> dict | None:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):] if "{" in text else text
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return obj if obj.get("verdict") in ("accept", "reject") else None


def verify(record: dict) -> dict:
    evidence = {
        "rule_id": record.get("rule_id"),
        "file": record.get("file"),
        "line": record.get("line"),
        "message": record.get("message"),
        "trace": record.get("trace"),
        "status": record.get("status"),
    }
    r = llm.chat(SYSTEM, json.dumps(evidence, ensure_ascii=False))
    if not r.get("ok"):
        return {"verdict": "unavailable", "error": r.get("error")}
    parsed = _parse(r["text"])
    if parsed is None:
        return {"verdict": "malformed", "raw": r["text"][:200]}
    return parsed


def run(records: list[dict], max_verify: int = 20) -> dict:
    """Rules accept/reject over the reportable set. Never edits trace or line."""
    rejected_now, accepted, unavailable = [], [], 0

    for rec in records[:max_verify]:
        if rec.get("status") != "confirmed":
            continue
        res = verify(rec)
        rec["verify"] = res
        if res["verdict"] == "reject":
            rec["status"] = "rejected"
            rec["reason"] = "复核否决：" + res.get("reason", "")
            rejected_now.append(rec)
        elif res["verdict"] == "accept":
            rec["evidence_level"] = "static+reviewed"
            accepted.append(rec)
        else:
            unavailable += 1

    if rejected_now:
        prior = load_rejected()
        prior.extend({"fingerprint": r["fingerprint"], "file": r["file"],
                      "reason": r["reason"]} for r in rejected_now)
        REJECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
        REJECTED_FILE.write_text(json.dumps(prior, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "accepted": len(accepted),
        "rejected": len(rejected_now),
        "unavailable": unavailable,
        "rejected_fingerprints": [r["fingerprint"] for r in rejected_now],
    }


def load_rejected() -> list[dict]:
    if not REJECTED_FILE.exists():
        return []
    try:
        return json.loads(REJECTED_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def filter_rejected(records: list[dict]) -> tuple[list[dict], list[dict]]:
    known = {r["fingerprint"] for r in load_rejected()}
    keep = [r for r in records if r["fingerprint"] not in known]
    return keep, [r for r in records if r["fingerprint"] in known]
