"""JSON CLI: the process boundary the dsh plugin calls.

Every tool exposed by core.toolset is reachable as
    python cli.py <tool> --args '{"path": "..."}'
or with the JSON object on stdin. One JSON object comes back on stdout, so the
host never has to parse prose.

Long work returns immediately when the tool is job-based (submit_job); the
caller polls job_status. Nothing here blocks for more than the tool's own budget.
"""

import argparse
import asyncio
import inspect
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Hosts (Node, shells) speak UTF-8; the Windows console default is a code page
# that silently mangles CJK arguments and output.
for stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from core import toolset  # noqa: E402

TOOLS = {name: fn for name, fn, _ in toolset.TOOLS}


def main() -> int:
    ap = argparse.ArgumentParser(prog="stardestroyer", description=__doc__)
    ap.add_argument("tool", nargs="?", help="tool name, e.g. audit_scan")
    ap.add_argument("--args", default=None, help="JSON object with tool arguments")
    ap.add_argument("--list", action="store_true", help="list available tools")
    ns = ap.parse_args()

    if ns.list:
        print(json.dumps([{"name": n, "doc": d} for n, _, d in toolset.TOOLS],
                         ensure_ascii=False, indent=2))
        return 0

    fn = TOOLS.get(ns.tool)
    if fn is None:
        print(json.dumps({"ok": False, "error": f"unknown tool: {ns.tool}"}, ensure_ascii=False))
        return 2

    raw = ns.args if ns.args is not None else (
        "" if sys.stdin.isatty() else sys.stdin.buffer.read().decode("utf-8", "replace"))
    try:
        kwargs = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        print(json.dumps({"ok": False, "error": f"invalid --args JSON: {exc}"}, ensure_ascii=False))
        return 2

    try:
        result = fn(**kwargs)
        if inspect.isawaitable(result):
            result = asyncio.run(result)
    except TypeError as exc:
        print(json.dumps({"ok": False, "error": f"bad arguments: {exc}"}, ensure_ascii=False))
        return 2
    except Exception as exc:  # a tool crash must still answer in JSON
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 1

    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if not (isinstance(result, dict) and result.get("ok") is False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
