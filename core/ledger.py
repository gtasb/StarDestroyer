"""Coverage ledger.

The unit is (file x attack class). A run must report what it covered and what
it did not; silence must never be read as "the rest is clean".
"""

import os
import pathlib
import re

from . import testcode

CLASSES = {
    "java": ["sqli", "cmd", "spel", "ssrf", "deser", "path", "xxe", "xss", "redirect"],
    "python": ["sqli", "cmd", "code", "deser", "ssrf", "ssti", "path", "redirect"],
    "go": ["sqli", "cmd", "ssrf", "path", "redirect", "ssti"],
    "js": ["sqli", "nosql", "cmd", "code", "deser", "ssrf", "ssti", "path", "xss", "redirect", "proto"],
    "php": ["sqli", "cmd", "code", "deser", "ssrf", "ssti", "path", "xss", "redirect"],
}

_RULE_CLASS = [
    ("nosql", "nosql"), ("prototype", "proto"), ("sqli", "sqli"), ("jdbc", "sqli"), ("command", "cmd"), ("cmd", "cmd"), ("code-injection", "code"),
    ("spel", "spel"), ("ssrf", "ssrf"), ("deser", "deser"), ("objectinputstream", "deser"),
    ("path-traversal", "path"), ("xxe", "xxe"), ("xss", "xss"), ("echo", "xss"), ("redirect", "redirect"), ("ssti", "ssti"),
]


def class_of(rule_id: str) -> str:
    rid = rule_id.lower()
    for token, cls in _RULE_CLASS:
        if token in rid:
            return cls
    return "other"


def source_files(root: str, lang: str) -> list[pathlib.Path]:
    p = pathlib.Path(root)
    if p.is_file():
        return [p] if p.suffix.lower() in EXTENSIONS.get(lang, []) else []
    test = testcode.skip(root)
    return [f for f in _all(p, lang) if not test(f.relative_to(p).as_posix())]


def test_files(root: str, langs: list[str]) -> int:
    """Source files left out because they are test code."""
    p, test = pathlib.Path(root), testcode.skip(root)
    return sum(test(f.relative_to(p).as_posix()) for lg in langs for f in _all(p, lg)) if p.is_dir() and testcode.skipping(root) else 0


def _all(p: pathlib.Path, lang: str) -> list[pathlib.Path]:
    exts = EXTENSIONS.get(lang, [])
    return _scripts(p)[0] if lang == "js" else [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts]


def _scripts(p: pathlib.Path) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    """(written by the project, generated or vendored) script files and directories."""
    mine, other = [], []
    for d, dirs, files in os.walk(p):
        base = pathlib.Path(d)
        drop = [x for x in dirs if x in _VENDOR or (x in ("dist", "build", "out") and "package.json" in files)]
        other += [base / x for x in drop]
        dirs[:] = [x for x in dirs if x not in drop]
        for f in files:
            if pathlib.Path(f).suffix.lower() in EXTENSIONS["js"]:
                (other if _BUILT.search(f) or _minified(base / f) else mine).append(base / f)
    return mine, other


def _minified(f: pathlib.Path) -> bool:
    """Generated code: a few enormous lines. Taint over it is slow and means nothing."""
    try:
        if f.stat().st_size < 50_000:
            return False
        head = f.read_bytes()[:200_000]
    except OSError:
        return False
    return len(head) / (head.count(b"\n") + 1) > 1000


def excluded(root: str) -> list[str]:
    """Generated and vendored scripts, left out of the audit on purpose, relative to root."""
    p = pathlib.Path(root)
    return [f.relative_to(p).as_posix() for f in _scripts(p)[1]] if p.is_dir() else []


def build(root: str, langs: list[str], findings: list[dict],
          scanned: list[str], errors: list[dict] | None = None) -> dict:
    """What the engine says it did, joined against what is on disk.

    covered    the engine scanned the file for this class and reported nothing
    candidate  there is at least one hit
    blocked    the engine touched the file but failed on it (parse error, timeout)
    skipped    the file is on disk and the engine never scanned it
    """
    base = pathlib.Path(root)
    base = base.parent if base.is_file() else base
    files = [(p, lg) for lg in langs for p in source_files(root, lg)]
    known = {c for lg in langs for c in CLASSES.get(lg, [])}

    # Engine paths are relative to its cwd, which is ours.
    def norm(path: str) -> str:
        return os.path.normcase(str(pathlib.Path(path).resolve()))

    seen = {norm(s) for s in scanned}
    hit: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (norm(f.get("file", "")), class_of(f.get("rule_id", "")))
        hit[key] = hit.get(key, 0) + 1

    blocked: dict[tuple[str, str], str] = {}
    for e in errors or []:
        if not e.get("path"):
            continue
        cls = class_of(e.get("rule_id") or "")
        for c in ([cls] if cls in known else known):
            blocked[(norm(e["path"]), c)] = e.get("message", "")[:160]

    units, unscanned, failed = [], [], {}
    for p, lg in files:
        rel, key = p.relative_to(base).as_posix(), norm(str(p))
        if key not in seen:
            unscanned.append(rel)
        for cls in CLASSES.get(lg, []):
            n, reason = hit.get((key, cls), 0), ""
            if key not in seen:
                status, reason = "skipped", "引擎未扫描该文件"
            elif (key, cls) in blocked:
                status, reason = "blocked", blocked[(key, cls)]
                failed[rel] = reason
            else:
                status = "covered"
            unit = {"surface": rel, "attack_class": cls,
                    "status": "candidate" if n else status, "hits": n}
            if reason:
                unit["reason"] = reason
            units.append(unit)

    def count(status: str) -> int:
        return sum(1 for u in units if u["status"] == status)

    return {
        "language": "+".join(langs),
        "root": str(root),
        "files": len(files),
        "units_total": len(units),
        "units_covered": count("covered"),
        "units_candidate": count("candidate"),
        "units_blocked": count("blocked"),
        "units_skipped": count("skipped"),
        "units_deferred": 0,
        "files_unscanned": unscanned,
        "files_failed": failed,
        "files_excluded": excluded(root) if "js" in langs else [],
        "files_tests": test_files(root, langs),
        "units": units,
    }


EXTENSIONS = {
    "java": [".java", ".kt"],
    "python": [".py"],
    "go": [".go"],
    "js": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"],
    "php": [".php", ".phtml", ".php5", ".php7", ".phps", ".inc"],
}
_VENDOR = {"node_modules", "bower_components", ".next", ".nuxt", ".output", ".svelte-kit"}
_BUILT = re.compile(r"\.(min|bundle|chunk)\.js$|\.d\.ts$", re.I)
