"""What people and reviewers said about findings, laid over the engine's verdict.

Only a person can take a finding off the report. A reviewer (see review.py) can
lower it, the engine may miss it, but hiding is a decision with an author.
Everything is keyed by suppress_key, so editing any file on the trace voids it.
"""

import pathlib
import time

from . import store

FILE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "decisions.json"

LABELS = {"confirmed": "人工确认", "false_positive": "误报", "accepted_risk": "接受风险"}
HIDES = {"false_positive", "accepted_risk"}
_BASE = ("status", "reason", "evidence_level", "severity")


def load() -> dict:
    return store.read(FILE, {})


def put(key: str, verdict: str, note: str = "", **meta) -> dict:
    """verdict "" clears the decision."""
    if not key:
        return {"ok": False, "error": "该发现的证据无法固定（文件不可读），不能标记"}
    if verdict and verdict not in LABELS:
        return {"ok": False, "error": f"未知结论: {verdict}"}
    with store.update(FILE, {}) as data:
        if verdict:
            data[key] = {"verdict": verdict, "note": note[:500],
                         "at": time.strftime("%Y-%m-%d %H:%M"), **meta}
        else:
            data.pop(key, None)
    return {"ok": True, "decision": load().get(key)}


def apply(records: list[dict]) -> list[dict]:
    """Overlay reviews, then decisions, in place; returns the records they hide.

    The engine's own verdict is kept in `base`, so this can run again on records
    that already carry an overlay -- and clearing a decision restores them.
    """
    from . import review
    said, reviews = load(), store.read(review.FILE, {})
    hidden = []
    for r in records:
        if "engine_status" in r:  # overlay format before reviews existed
            r["status"], r["reason"] = r.pop("engine_status"), r.pop("engine_reason", "")
        base = r.setdefault("base", {k: r.get(k) for k in _BASE})
        r.update(base)
        r.pop("decision", None)
        r.pop("review", None)
        key = r.get("suppress_key") or ""
        if key in reviews:
            review.apply_one(r, reviews[key])
        d = said.get(key)
        if not d:
            continue
        r["decision"] = d
        r["reason"] = LABELS[d["verdict"]] + (f"：{d['note']}" if d.get("note") else "")
        if d["verdict"] in HIDES:
            r["status"] = "rejected"
            hidden.append(r)
        else:
            r["status"] = "confirmed"
    return hidden
