"""Settings that outlive a single shell.

Keys live in %USERPROFILE%\\.stardestroyer\\config.json and are applied to the
process environment, because every engine reads its credential from an env var.
Secrets are never returned in full: the API exposes a masked form plus whether a
value exists at all.
"""

import json
import os
import pathlib

CONFIG_DIR = pathlib.Path.home() / ".stardestroyer"
CONFIG_FILE = CONFIG_DIR / "config.json"

SECRET_KEYS = ("DEEPSEEK_API_KEY", "TAVILY_API_KEY", "NVD_API_KEY")
PATH_KEYS = ("OPENGREP_BIN", "TABBY_JAR", "OPENSCA_BIN")
OTHER_KEYS = ("SD_LOG_LEVEL", "AUDIT_INTERFILE_DEPTH")
ALL_KEYS = SECRET_KEYS + PATH_KEYS + OTHER_KEYS


def load() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save(values: dict) -> dict:
    data = load()
    for k, v in values.items():
        if k not in ALL_KEYS:
            continue
        if v is None or v == "":
            data.pop(k, None)
        else:
            data[k] = str(v).strip()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    apply()
    return data


def apply() -> None:
    """Environment wins over the file: an explicit export must not be shadowed."""
    for k, v in load().items():
        if k in ALL_KEYS and not os.environ.get(k):
            os.environ[k] = v


def _mask(v: str) -> str:
    if not v:
        return ""
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}…{v[-4:]}"


def view() -> dict:
    """What the settings page may see: masked secrets, real paths."""
    data = load()
    out = {}
    for k in ALL_KEYS:
        env_v = os.environ.get(k, "")
        file_v = data.get(k, "")
        value = env_v or file_v
        out[k] = {
            "value": _mask(value) if k in SECRET_KEYS else value,
            "set": bool(value),
            "source": "env" if env_v else ("file" if file_v else ""),
            "secret": k in SECRET_KEYS,
        }
    return {"path": str(CONFIG_FILE), "keys": out}
