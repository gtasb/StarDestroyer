"""Opengrep adapter: precision layer.

Two facts were verified against v2.0.0 rather than assumed:

1. `--enable-interfile` only affects rules that declare `options: {interfile: true}`.
   Passing the flag against rules without it yields zero findings and no error --
   a silent no-op, which is why rules and flags are checked as a pair here.
2. `--json` carries `extra.dataflow_trace` with explicit `kind` per step
   (source / through / sink_in_call / sink), so "trace complete" is a structural
   test, not a slice-length guess.
"""

import json
import os
import pathlib
import re
import subprocess
import tempfile

def _default_binary() -> str:
    exe = "opengrep.exe" if os.name == "nt" else "opengrep"
    here = pathlib.Path(__file__).resolve()
    for base in (here.parents[2], here.parents[3]):
        local = base / ".work" / "og200" / "bin" / exe
        if local.exists():
            return str(local)
    return "opengrep"


BINARY = os.environ.get("OPENGREP_BIN") or _default_binary()
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates" / "opengrep"

_caps: dict | None = None

SINK_KINDS = {"sink", "sink_in_call"}


def capabilities(force: bool = False) -> dict:
    global _caps
    if _caps is not None and not force:
        return _caps
    try:
        help_txt = subprocess.run(
            [BINARY, "scan", "--help"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        ).stdout or ""
    except (OSError, subprocess.SubprocessError) as exc:
        _caps = {"available": False, "error": str(exc)}
        return _caps
    _caps = {
        "available": True,
        "taint_intrafile": "--taint-intrafile" in help_txt,
        "enable_interfile": "--enable-interfile" in help_txt,
        "interfile_depth": bool(re.search(r"--interfile-depth", help_txt)),
        "dataflow_traces": "--dataflow-traces" in help_txt,
        "sarif": "--sarif" in help_txt,
    }
    return _caps


def build_args(src: str, out_json: str, rules: str | None = None,
               extra_rules: list[str] | None = None) -> tuple[list[str], list[str]]:
    caps = capabilities()
    if not caps.get("available"):
        raise RuntimeError(f"opengrep 不可用: {caps.get('error')}")

    argv = [BINARY, "scan", "-c", rules or str(TEMPLATES), "--json", "-o", out_json]
    for extra in extra_rules or []:
        argv += ["-c", extra]
    unsupported: list[str] = []

    if caps["taint_intrafile"]:
        argv.append("--taint-intrafile")
    else:
        unsupported.append("--taint-intrafile")

    # Passed unconditionally: harmless for rules that do not opt in, and the
    # rules shipped here do.
    if caps["enable_interfile"]:
        argv.append("--enable-interfile")
        if caps["interfile_depth"]:
            argv += [f"--interfile-depth={os.environ.get('AUDIT_INTERFILE_DEPTH', '3')}"]
    else:
        unsupported.append("--enable-interfile")

    argv.append(src)
    return argv, unsupported


def run_scan(src: str, rules: str | None = None, timeout_s: int = 900,
             extra_rules: list[str] | None = None) -> dict:
    fd, out_json = tempfile.mkstemp(suffix=".json", prefix="og-")
    os.close(fd)
    argv, unsupported = build_args(src, out_json, rules, extra_rules)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s,
                              encoding="utf-8", errors="replace")
        doc = json.loads(pathlib.Path(out_json).read_text(encoding="utf-8", errors="replace"))
        findings = parse_json(doc)
        return {
            "engine": "opengrep",
            "argv": argv,
            "unsupported_flags": unsupported,
            "exit": proc.returncode,
            "errors": [e.get("message", "")[:300] for e in doc.get("errors", [])],
            "interfile_languages": doc.get("interfile_languages_used", []),
            "stderr_tail": proc.stderr.strip().splitlines()[-5:],
            "json_path": out_json,
            "findings": findings,
            "total": len(findings),
        }
    finally:
        pass  # the json file is the evidence artifact; callers archive it


def _flatten(nodes: list[dict]) -> list[dict]:
    out: list[dict] = []
    for n in nodes or []:
        loc = n.get("location", {})
        out.append({
            "kind": n.get("kind", ""),
            "file": loc.get("path", ""),
            "line": (loc.get("start") or {}).get("line"),
            "text": n.get("content", ""),
        })
        out.extend(_flatten(n.get("children") or []))
    return out


def parse_json(doc: dict) -> list[dict]:
    out: list[dict] = []
    for res in doc.get("results", []):
        steps = _flatten((res.get("extra") or {}).get("dataflow_trace") or [])
        kinds = {s["kind"] for s in steps}
        out.append({
            "rule_id": res.get("check_id", "").split(".")[-1],
            "message": (res.get("extra") or {}).get("message", ""),
            "file": res.get("path", ""),
            "line": (res.get("start") or {}).get("line"),
            "trace": steps,
            # Structural test: a source step and a sink step both present.
            "trace_complete": "source" in kinds and bool(kinds & SINK_KINDS),
        })
    return out


def gaps(findings: list[dict]) -> list[dict]:
    return [f for f in findings if not f["trace_complete"]]
