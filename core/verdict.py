"""Verdict logic. Hard rules, no LLM here.

An LLM may explain a verdict; it may never produce one. Every status this
module returns is derivable from engine output alone.
"""

CONFIRMED = "confirmed"
NEEDS_REVIEW = "needs_review"
NEEDS_DYNAMIC = "needs_dynamic"
NO_FINDING = "no_finding"


def _all_in_source(chain: dict, source_root: str) -> bool:
    root = source_root.replace("\\", "/").rstrip("/") + "/"
    for node in chain.get("nodes", []):
        f = (node.get("file") or "").replace("\\", "/")
        if not f or not f.startswith(root):
            return False
    return bool(chain.get("nodes"))


def judge(opengrep_hit: dict | None, tabby_chain: dict | None, source_root: str) -> dict:
    og = opengrep_hit
    tb = tabby_chain

    if og and og.get("trace_complete"):
        return {
            "status": CONFIRMED,
            "reason": "Opengrep 语句级 trace 完整",
            "evidence": og.get("trace_path"),
            "source": "opengrep",
        }

    if tb and not og:
        if _all_in_source(tb, source_root):
            return {
                "status": NEEDS_REVIEW,
                "reason": "图有路径但污点未验证，可能参数不可控",
                "missing": "参数可控性证明",
                "source": "tabby",
            }
        return {
            "status": NEEDS_DYNAMIC,
            "reason": "链跨第三方库，静态不可验",
            "missing": "运行时验证",
            "source": "tabby",
        }

    if tb and og and not og.get("trace_complete"):
        return {
            "status": NEEDS_REVIEW,
            "reason": "trace 不完整，存在断点",
            "missing": og.get("gaps", []),
            "source": "opengrep+tabby",
        }

    # Opengrep-only phase: a hit whose trace stops short is still a hit.
    # Dropping it to no_finding would be a silent false negative.
    if og and not og.get("trace_complete"):
        return {
            "status": NEEDS_REVIEW,
            "reason": "trace 不完整，存在断点",
            "missing": og.get("gaps") or ["污点链断点"],
            "source": "opengrep",
        }

    return {"status": NO_FINDING, "reason": "两引擎均无命中", "source": "none"}


REPORTABLE = {CONFIRMED, NEEDS_REVIEW, NEEDS_DYNAMIC}


def is_reportable(v: dict) -> bool:
    return v.get("status") in REPORTABLE
