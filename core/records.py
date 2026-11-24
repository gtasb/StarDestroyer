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
# rejected       falsified; kept on disk so the next wave does not resubmit it
STATUSES = {"confirmed", "needs_review", "needs_dynamic", "rejected"}


def _rel(path: str, root: str) -> str:
    try:
        return pathlib.Path(path).resolve().relative_to(pathlib.Path(root).resolve()).as_posix()
    except ValueError:
        return pathlib.Path(path).as_posix()


def fingerprint(finding: dict, root: str) -> str:
    rel = _rel(finding.get("file", ""), root)
    sink = ""
    for step in reversed(finding.get("trace") or []):
        if step.get("kind") in ("sink", "sink_in_call"):
            sink = step.get("text", "")
            break
    if not sink:
        sink = (finding.get("message") or "").strip()[:80]
    raw = f"{finding.get('rule_id', '')}|{rel}|{sink}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make(finding: dict, verd: dict, root: str) -> dict:
    return {
        "fingerprint": fingerprint(finding, root),
        "rule_id": finding.get("rule_id", ""),
        "file": _rel(finding.get("file", ""), root),
        "line": finding.get("line"),
        "message": finding.get("message", ""),
        "status": verd.get("status"),
        "evidence_level": "static" if verd.get("status") == "confirmed" else "none",
        "reason": verd.get("reason", ""),
        "missing": verd.get("missing"),
        "trace": finding.get("trace") or [],
        "source_tool": verd.get("source", ""),
    }


def merge_rejected(records: list[dict], rejected: list[dict]) -> list[dict]:
    """Re-apply prior rejections so a re-run cannot resubmit a falsified hit."""
    known = {r["fingerprint"] for r in rejected}
    return [r for r in records if r["fingerprint"] not in known], rejected
