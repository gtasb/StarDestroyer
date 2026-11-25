"""Console launcher.

Exists so the app can be started from any cwd: uvicorn's app-dir handling is
what makes `web.server` importable.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8770
    uvicorn.run("web.server:app", host="127.0.0.1", port=port, app_dir=str(ROOT))
