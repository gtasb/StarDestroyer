"""SARIF 2.1.0 export.

The engine speaks JSON (it carries the kinded dataflow trace we judge on);
SARIF is the interchange format consumers expect. One scan, two artifacts.
"""

import json
import pathlib

TOOL = {
    "driver": {
        "name": "stardestroyer",
        "informationUri": "https://github.com/opengrep/opengrep",
        "rules": [],
    }
}


def to_sarif(findings: list[dict]) -> dict:
    rules: dict[str, int] = {}
    results = []

    for f in findings:
        rid = f.get("rule_id", "unknown")
        if rid not in rules:
            rules[rid] = len(rules)
            TOOL["driver"]["rules"].append({"id": rid, "name": rid})
        v = f.get("verdict") or {}
        status = f.get("status") or v.get("status")
        reason = f.get("reason") or v.get("reason", "")
        results.append({
            "ruleId": rid,
            "ruleIndex": rules[rid],
            "level": "error" if status == "confirmed" else "warning",
            "message": {"text": f"{f.get('message', '')} [{status}]"},
            "partialFingerprints": {"stableFingerprint": f.get("fingerprint", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": f.get("line") or 1},
                }
            }],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        {"location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": s.get("file", "")},
                                "region": {"startLine": s.get("line") or 1},
                            },
                            "message": {"text": f"{s.get('kind', '')}: {s.get('text', '')}"},
                        }}
                        for s in (f.get("trace") or [])
                    ]
                }]
            }] if f.get("trace") else [],
            "properties": {"status": status, "reason": reason},
        })

    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": TOOL, "results": results}]}


def write_sarif(findings: list[dict], path: str) -> str:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_sarif(findings), ensure_ascii=False, indent=2), encoding="utf-8")
    return str(p)
