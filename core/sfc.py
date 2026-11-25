"""Single-file components (.vue, .svelte) for an engine that cannot parse them.

The script blocks are written, at their original lines, to a TypeScript file in a
temporary tree; afterwards every path the engine reports is mapped back. Imports
between components are not followed by the engine -- the agent does that.
"""

import os
import pathlib
import re
import tempfile

EXTENSIONS = (".vue", ".svelte")
_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)


def script(text: str) -> str:
    """Everything but the script bodies blanked; offsets and lines survive."""
    out = re.sub(r"[^\n]", " ", text)
    for m in _SCRIPT.finditer(text):
        out = out[:m.start(2)] + m.group(2) + out[m.end(2):]
    return out


def _is_jsx(text: str) -> bool:
    return any(re.search(r"lang\s*=\s*[\"'](?:t|j)sx[\"']", m.group(1)) for m in _SCRIPT.finditer(text))


class Shadow:
    """Context manager: `.dir` is an extra scan target, or "" when there is nothing to add."""

    def __init__(self, files: list[pathlib.Path]):
        self.files = files
        self.dir = ""
        self._tmp = None
        self._back: dict[str, str] = {}
        self.bare: list[str] = []  # no script block: nothing for the engine in there

    def __enter__(self):
        if not self.files:
            return self
        self._tmp = tempfile.TemporaryDirectory(prefix="sd-sfc-", ignore_cleanup_errors=True)
        root = pathlib.Path(self._tmp.name).resolve()
        for i, f in enumerate(self.files):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            body = script(text)
            if not body.strip():
                self.bare.append(str(f))
                continue
            to = root / str(i) / (f.stem + (".tsx" if _is_jsx(text) else ".ts"))
            to.parent.mkdir()
            to.write_text(body, encoding="utf-8")
            self._back[os.path.normcase(str(to))] = str(f)
        if self._back:
            self.dir = str(root)
        return self

    def __exit__(self, *exc):
        if self._tmp:
            self._tmp.cleanup()

    def back(self, path: str) -> str:
        if not path or not self._back:
            return path
        return self._back.get(os.path.normcase(str(pathlib.Path(path).resolve())), path)

    def restore(self, res: dict) -> dict:
        """Map every path in an engine result back to the component."""
        for f in res.get("findings") or []:
            f["file"] = self.back(f["file"])
            for s in f.get("trace") or []:
                s["file"] = self.back(s["file"])
        res["scanned"] = [self.back(p) for p in res.get("scanned") or []] + self.bare
        for e in res.get("error_items") or []:
            e["path"] = self.back(e["path"])
        return res
