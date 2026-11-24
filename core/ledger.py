"""Coverage ledger.

The unit is (file x attack class). A run must report what it covered and what
it did not; silence must never be read as "the rest is clean".
"""

import pathlib

CLASSES = {
    "java": ["sqli", "cmd", "spel", "ssrf", "deser"],
    "python": ["sqli", "cmd", "deser", "ssrf"],
    "go": ["sqli", "cmd", "ssrf"],
}

_RULE_CLASS = [
    ("sqli", "sqli"),
    ("jdbc", "sqli"),
    ("command", "cmd"),
    ("cmd", "cmd"),
    ("spel", "spel"),
    ("ssrf", "ssrf"),
    ("deser", "deser"),
    ("objectinputstream", "deser"),
]


def class_of(rule_id: str) -> str:
    rid = rule_id.lower()
    for token, cls in _RULE_CLASS:
        if token in rid:
            return cls
    return "other"


def build(root: str, lang: str, findings: list[dict], exts: dict[str, list[str]]) -> dict:
    files = [p for p in pathlib.Path(root).rglob("*")
             if p.is_file() and p.suffix.lower() in exts.get(lang, [])]

    hit: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (pathlib.Path(f.get("file", "")).as_posix(), class_of(f.get("rule_id", "")))
        hit[key] = hit.get(key, 0) + 1

    units = []
    for p in files:
        rel = p.relative_to(pathlib.Path(root)).as_posix()
        for cls in CLASSES.get(lang, []):
            n = hit.get((rel, cls), 0) + hit.get((p.as_posix(), cls), 0)
            units.append({
                "surface": rel,
                "attack_class": cls,
                "status": "candidate" if n else "covered",
                "hits": n,
            })

    covered = sum(1 for u in units if u["status"] == "covered")
    return {
        "language": lang,
        "root": str(root),
        "files": len(files),
        "units_total": len(units),
        "units_covered": covered,
        "units_candidate": len(units) - covered,
        "units_blocked": 0,
        "units_deferred": 0,
        "units": units,
    }


EXTENSIONS = {
    "java": [".java", ".kt"],
    "python": [".py"],
    "go": [".go"],
}
