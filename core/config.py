"""Settings that outlive a single shell.

Keys live in %USERPROFILE%\\.stardestroyer\\config.json and are applied to the
process environment, because every engine reads its credential from an env var.
Secrets are never returned in full: the API exposes a masked form plus whether a
value exists at all.
"""

import os
import pathlib

from . import providers, store

CONFIG_DIR = pathlib.Path.home() / ".stardestroyer"
CONFIG_FILE = CONFIG_DIR / "config.json"

SECRET_KEYS = ("DEEPSEEK_API_KEY", "TAVILY_API_KEY", "NVD_API_KEY")
PATH_KEYS = ("OPENGREP_BIN", "TABBY_JAR", "OPENSCA_BIN", "DSH_BIN", "GITLEAKS_BIN", "BUILD_JAVA_HOME")
OTHER_KEYS = ("SD_LOG_LEVEL", "AUDIT_INTERFILE_DEPTH", "REVIEW_MAX", "AUDIT_CONCURRENCY", "AUDIT_ACCESS", "SCA_OSV", "SCA_INDIRECT", "SCA_MAVEN", "POM_ROOTS",
              "LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL")
ALL_KEYS = SECRET_KEYS + PATH_KEYS + OTHER_KEYS

# What the user exported before we touched anything. apply() writes into the same
# environment, so without this snapshot our own first write would look like theirs.
_EXPORTED = {k for k in os.environ if os.environ[k] and (k in ALL_KEYS or providers.is_key(k))}


def allowed(key: str) -> bool:
    return key in ALL_KEYS or providers.is_key(key)


def load() -> dict:
    data = store.read(CONFIG_FILE, {})
    return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def save(values: dict) -> dict:
    with store.update(CONFIG_FILE, {}) as data:
        for k, v in values.items():
            if not allowed(k):
                continue
            if v is None or v == "":
                data.pop(k, None)
            else:
                data[k] = str(v).strip()
    apply()
    return load()


def apply() -> None:
    """Environment wins over the file: an explicit export must not be shadowed."""
    data = load()
    for k in {*ALL_KEYS, *filter(providers.is_key, data), *filter(providers.is_key, os.environ)}:
        if k in _EXPORTED:
            continue
        if data.get(k):
            os.environ[k] = data[k]
        else:
            os.environ.pop(k, None)


def _mask(v: str) -> str:
    if not v:
        return ""
    return "********" if len(v) < 16 else f"{v[:4]}…{v[-4:]}"


def view() -> dict:
    """What the settings page may see: masked secrets, real paths."""
    data = load()
    out = {}
    for k in (*ALL_KEYS, *sorted(x for x in {*data, *os.environ} if providers.is_key(x))):
        value = os.environ.get(k, "") or data.get(k, "")
        out[k] = {
            "value": _mask(value) if k in SECRET_KEYS or providers.is_key(k) else value,
            "set": bool(value),
            "source": "env" if k in _EXPORTED else ("file" if data.get(k) else ""),
            "secret": k in SECRET_KEYS or providers.is_key(k),
        }
    return {"path": str(CONFIG_FILE), "keys": out}
