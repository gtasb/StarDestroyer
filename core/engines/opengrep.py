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


def binary() -> str:
    return os.environ.get("OPENGREP_BIN") or _default_binary()
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates" / "opengrep"

_caps: dict[str, dict] = {}

SINK_KINDS = {"sink", "sink_in_call"}


def capabilities(force: bool = False) -> dict:
    exe = binary()
    if exe in _caps and not force:
        return _caps[exe]
    try:
        help_txt = subprocess.run(
            [exe, "scan", "--help"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        ).stdout or ""
    except (OSError, subprocess.SubprocessError) as exc:
        # Not cached: fixing the path in settings must work without a restart.
        return {"available": False, "error": str(exc)}
    _caps[exe] = {
        "available": True,
        "taint_intrafile": "--taint-intrafile" in help_txt,
        "enable_interfile": "--enable-interfile" in help_txt,
        "interfile_depth": bool(re.search(r"--interfile-depth", help_txt)),
        "dataflow_traces": "--dataflow-traces" in help_txt,
        "sarif": "--sarif" in help_txt,
        "no_git_ignore": "--no-git-ignore" in help_txt,
        "disable_nosem": "--disable-nosem" in help_txt,
        "ignore_semgrepignore": "--x-ignore-semgrepignore-files" in help_txt,
        "max_target_bytes": "--max-target-bytes" in help_txt,
    }
    return _caps[exe]


DEPTH = "20"  # the engine's own default is 3, which loses ordinary controller-to-mapper chains


def depth() -> str:
    d = os.environ.get("AUDIT_INTERFILE_DEPTH") or DEPTH
    if not d.isdigit():
        raise RuntimeError(f"AUDIT_INTERFILE_DEPTH 必须是数字，当前为 {d!r}")
    return d


def build_args(src: str, out_json: str, rules: str | None = None,
               extra_rules: list[str] | None = None, also: list[str] = (),
               exclude: list[str] = (), at: str | None = None) -> tuple[list[str], list[str]]:
    caps = capabilities()
    if not caps.get("available"):
        raise RuntimeError(f"opengrep 不可用: {caps.get('error')}")

    argv = [binary(), "scan", "-c", rules or str(TEMPLATES), "--json", "-o", out_json]
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
            argv += [f"--interfile-depth={at or depth()}"]
    else:
        unsupported.append("--enable-interfile")

    # The audited tree is untrusted: a `// nosem` comment, a .gitignore or a
    # .semgrepignore inside it must not be able to switch the audit off. Where a
    # flag is missing, the ledger still shows the files that were not scanned.
    for cap, flag in (("disable_nosem", "--disable-nosem"),
                      ("no_git_ignore", "--no-git-ignore"),
                      ("ignore_semgrepignore", "--x-ignore-semgrepignore-files")):
        if caps.get(cap):
            argv.append(flag)
        else:
            unsupported.append(flag)
    if caps.get("max_target_bytes"):
        argv.append(f"--max-target-bytes={MAX_TARGET_BYTES}")
    else:
        unsupported.append("--max-target-bytes")

    room = 20_000  # Windows caps a command line; what does not fit is merely scanned as well
    for d in (*EXCLUDE, *exclude):
        room -= len(d) + 13
        if room > 0:
            argv.append(f"--exclude={d}")
    argv += [src, *also]
    return argv, unsupported


# Other people's code and build output, whatever the caller adds. See ledger.excluded.
EXCLUDE = ("node_modules", "bower_components", ".next", ".nuxt", ".output", ".svelte-kit", "*.min.js", "*.bundle.js", "*.chunk.js")

# 0 = clean, 1 = findings reported as errors, 3 = some target failed to parse.
# Everything else means the engine did not do the job it was asked to do.
OK_EXITS = {0, 1, 3}
MAX_TARGET_BYTES = 10_000_000


def _failed(error: str, **extra) -> dict:
    from .. import logging
    logging.warn("opengrep", "scan failed", error=error[:300])
    return {"engine": "opengrep", "ok": False, "error": error, "findings": [], "total": 0,
            "errors": [error], "error_items": [], "scanned": [], "unsupported_flags": [],
            "interfile_languages": [], **extra}


def run_scan(src: str, rules: str | None = None, timeout_s: int = 900,
             extra_rules: list[str] | None = None, also: list[str] = (), exclude: list[str] = (), at: str | None = None) -> dict:
    """Never raises for engine trouble: a failed run is ok=False, not zero hits."""
    from .. import logging, proc as procs
    fd, out_json = tempfile.mkstemp(suffix=".json", prefix="og-")
    os.close(fd)
    try:
        return _run(src, rules, timeout_s, extra_rules, also, exclude, out_json, logging, procs, at)
    finally:
        pathlib.Path(out_json).unlink(missing_ok=True)


def _run(src, rules, timeout_s, extra_rules, also, exclude, out_json, logging, procs, at=None) -> dict:
    try:
        argv, unsupported = build_args(src, out_json, rules, extra_rules, also, exclude, at)
        logging.debug("opengrep", "run", argv=" ".join(argv[-4 - len(also):]))
        proc = procs.run(argv, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return _failed(f"opengrep 超时（{timeout_s}s）")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return _failed(str(exc))
    stderr_tail = proc.stderr.strip().splitlines()[-5:]
    try:
        doc = json.loads(pathlib.Path(out_json).read_text(encoding="utf-8", errors="replace"))
        findings = parse_json(doc)
    except (OSError, ValueError) as exc:
        return _failed(f"opengrep 未产出可解析的 JSON（exit={proc.returncode}）: {exc}",
                       exit=proc.returncode, stderr_tail=stderr_tail)

    errors = doc.get("errors", [])
    fatal = [e for e in errors if e.get("level") == "error"]
    ok = proc.returncode in OK_EXITS and not fatal
    error = None
    if not ok:
        detail = "; ".join(e.get("message", "")[:200] for e in (fatal or errors)[:3])
        error = f"opengrep 执行失败（exit={proc.returncode}）" + (f": {detail}" if detail else "")
    logging.info("opengrep", "scan done", exit=proc.returncode, findings=len(findings),
                 interfile=doc.get("interfile_languages_used", []))
    return {
        "engine": "opengrep",
        "ok": ok,
        "error": error,
        "argv": argv,
        "unsupported_flags": unsupported,
        "exit": proc.returncode,
        "errors": [e.get("message", "")[:300] for e in errors],
        "error_items": [{"path": e.get("path", ""), "rule_id": e.get("rule_id", ""),
                         "level": e.get("level", ""), "message": e.get("message", "")[:300]}
                        for e in errors],
        "scanned": (doc.get("paths") or {}).get("scanned") or [],
        "interfile_languages": doc.get("interfile_languages_used", []),
        "stderr_tail": stderr_tail,
        "raw": doc,
        "findings": findings,
        "total": len(findings),
    }


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


_SEVERITY = {"ERROR": "high", "CRITICAL": "critical", "HIGH": "high", "WARNING": "medium",
             "MEDIUM": "medium", "INFO": "low", "LOW": "low"}


def _cwe(meta: dict) -> str:
    cwe = meta.get("cwe") or ""
    return str(cwe[0] if isinstance(cwe, list) and cwe else cwe or "")


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
            "severity": _SEVERITY.get((res.get("extra") or {}).get("severity", ""), "medium"),
            "cwe": _cwe((res.get("extra") or {}).get("metadata") or {}),
            "trace": steps,
            # Structural test: a source step and a sink step both present.
            "trace_complete": "source" in kinds and bool(kinds & SINK_KINDS),
        })
    return out


def gaps(findings: list[dict]) -> list[dict]:
    return [f for f in findings if not f["trace_complete"]]
