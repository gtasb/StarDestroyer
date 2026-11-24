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
    uvicorn.run("web.server:app", host="127.0.0.1", port=8770, app_dir=str(ROOT))
