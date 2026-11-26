"""Which files are test code, and whether it is audited.

Test code is not deployed, so it is left out unless asked for. What is left out is
counted and shown: a directory called test is a choice of the audited project, too.
"""

import os
import pathlib
import re

from .profile import SKIP_DIRS

_DIR = re.compile(r"(?:unit|integration|functional|android|common|jvm|js)?[-_]?tests?|__tests__|__mocks__|test[-_]?(?:data|fixtures)|e2e|cypress", re.I)
_FILE = re.compile(r"_test\.go$|\.(?:test|spec|stories)\.[cm]?[jt]sx?$|^test_[^/]*\.py$|_test\.py$|^conftest\.py$|\.cy\.[jt]sx?$", re.I)


def is_test(rel: str) -> bool:
    """`rel` is relative to the project. What is under src/main is shipped, whatever its package is called."""
    *dirs, name = str(rel).replace("\\", "/").strip("/").split("/")
    low = [d.lower() for d in dirs]
    main = next((i for i in range(len(low) - 1) if low[i] == "src" and low[i + 1] == "main"), None)
    if main is not None:
        return any(_DIR.fullmatch(d) for d in dirs[:main])
    return any(_DIR.fullmatch(d) for d in dirs) or bool(_FILE.search(name))


def skipping(root) -> bool:
    """The project's choice, else the setting; on unless turned off."""
    from . import projects
    mine = (projects.get(projects.project_id(str(root))) or {}).get("tests") or ""
    return (mine or os.environ.get("SCAN_TESTS") or "0") != "1"


def skip(root):
    """rel -> whether to leave it out of this project's audit."""
    return is_test if skipping(root) and pathlib.Path(root).is_dir() else lambda rel: False


def paths(root) -> list[str]:
    """Directories and files to keep engines out of, topmost first; [] when tests are wanted."""
    base = pathlib.Path(root)
    if not base.is_dir() or not skipping(root):
        return []
    out = []
    for here, dirs, files in os.walk(base):
        at = pathlib.Path(here).relative_to(base).as_posix()
        at = "" if at == "." else at + "/"
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for d in [d for d in dirs if is_test(f"{at}{d}/x")]:
            dirs.remove(d)
            out.append(f"{at}{d}")
        out += [f"{at}{f}" for f in files if is_test(f"{at}{f}")]
    return sorted(out, key=lambda p: (p.count("/"), p))
