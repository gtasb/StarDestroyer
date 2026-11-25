"""Which model the dsh sessions use.

dsh routes models; this only records the choice and turns it into a patch layer.
Providers and models come from the installed dsh (dsh-plugin/catalog.mjs).
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import urllib.error
from urllib.parse import urlsplit

from . import net, proc

CATALOG = pathlib.Path(__file__).resolve().parents[1] / "dsh-plugin" / "catalog.mjs"
OFFICIAL = "deepseek-official"  # dsh's own DeepSeek route
KEY_ENV = "SD_LLM_KEY"          # how the chosen key reaches dsh, whatever the provider
DSH_DEFAULT = "deepseek-flash"
OFFICIAL_BASE = "https://api.deepseek.com"

# Not in dsh's catalog: an OpenAI-compatible address is all they need.
EXTRA = [
    {"id": "dashscope", "name": "阿里云百炼（通义千问）", "base": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
    {"id": "volcengine", "name": "火山方舟（豆包）", "base": "https://ark.cn-beijing.volces.com/api/v3"},
    {"id": "siliconflow", "name": "硅基流动", "base": "https://api.siliconflow.cn/v1"},
    {"id": "ollama", "name": "Ollama（本机）", "base": "http://127.0.0.1:11434/v1", "local": True},
    {"id": "lmstudio", "name": "LM Studio（本机）", "base": "http://127.0.0.1:1234/v1", "local": True},
    {"id": "custom", "name": "自定义（OpenAI 兼容）", "base": "", "local": True},
]
_EXTRA = {e["id"]: e for e in EXTRA}
_cache: dict[str, list] = {}


def key_name(pid: str) -> str:
    return "DEEPSEEK_API_KEY" if pid == OFFICIAL else "LLM_KEY_" + re.sub(r"[^A-Z0-9]", "_", pid.upper())


def is_key(name: str) -> bool:
    return bool(re.fullmatch(r"LLM_KEY_[A-Z0-9_]{1,60}", name))


def catalog() -> list[dict]:
    """[{id, name, env, base, models}] of the installed dsh; empty when there is none."""
    from . import agents
    home, node = agents.dsh_home(), shutil.which("node")
    if not home or not node:
        return []
    if str(home) not in _cache:
        try:
            r = proc.run([node, str(CATALOG), str(home / "node_modules")], timeout=30)
            _cache[str(home)] = json.loads(r.stdout)
        except (ValueError, OSError, subprocess.SubprocessError):
            return []
    return _cache[str(home)]


def listing() -> list[dict]:
    """What the settings page offers."""
    out = [{"id": OFFICIAL, "name": "DeepSeek（dsh 官方路由）", "base": "", "local": False, "models": [], "env": []}]
    out += [{**p, "local": False} for p in catalog()]
    out += [{"env": [], "models": [], "local": False, **e} for e in EXTRA]
    for p in out:
        p["key_name"] = key_name(p["id"])
        p["has_key"] = bool(os.environ.get(p["key_name"])) or any(os.environ.get(e) for e in p["env"])
    return out


# ---- what a service says it has ---------------------------------------------------
_NOT_CHAT = re.compile(r"embed|rerank|whisper|\btts\b|-tts|speech|transcri|\basr\b|dall-e|moderation|gpt-image|imagen|\bveo\b|stable-diffusion|flux|cosyvoice|wanx?\d|bge-|\bocr\b", re.I)


def insecure(base: str) -> bool:
    u = urlsplit(base)
    return u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"))


def _urls(base: str) -> list[str]:
    """Where an address may keep its model list, most likely first."""
    base = base.rstrip("/")
    u = urlsplit(base)
    out = [f"{base}/models"] if re.search(r"/v\d+\w*$", u.path) else [f"{base}/v1/models", f"{base}/models"]
    out.append(f"{u.scheme}://{u.netloc}/v1/models")  # .../anthropic and the like sit beside it
    return list(dict.fromkeys(out))


def _parse(doc) -> list[str]:
    rows = doc if isinstance(doc, list) else next((doc[k] for k in ("data", "models") if isinstance(doc, dict) and isinstance(doc.get(k), list)), None)
    if rows is None:
        raise ValueError("返回的不是模型列表")
    out = []
    for r in rows:
        if isinstance(r, dict):
            how = r.get("supportedGenerationMethods")
            if isinstance(how, list) and "generateContent" not in how:
                continue
            r = r.get("id") or r.get("name") or r.get("model")
        if isinstance(r, str) and r:
            out.append(r.removeprefix("models/"))
    return list(dict.fromkeys(out))


def models(pid: str, base: str = "", key: str = "") -> dict:
    """Ask the service itself. {ok, models: [{id, name, context}], url, hidden} or {ok: False, error}."""
    p = next((x for x in listing() if x["id"] == pid), None)
    if not p:
        return {"ok": False, "error": f"没有这个服务商: {pid}"}
    own, c = OFFICIAL_BASE if pid == OFFICIAL else p["base"], chosen()
    mine = [own, *([c["base"]] if c["id"] == pid and c["base"] else [])]
    base = (base.strip() or (c["base"] if c["id"] == pid else "") or own).rstrip("/")
    if not base:
        return {"ok": False, "error": "这个服务商没有固定的接口地址，先填接口地址"}
    if insecure(base):
        return {"ok": False, "error": "接口地址必须是 https（本机除外）"}
    key = key.strip()
    if not key and base in [m.rstrip("/") for m in mine]:
        # A stored key goes to the address it was stored for, nowhere else.
        key = os.environ.get(p["key_name"], "") or next((os.environ[e] for e in p["env"] if os.environ.get(e)), "")
    elif not key and not p["local"] and p["has_key"]:
        return {"ok": False, "error": "接口地址是新填的：先保存，或在这里填一次 key 再获取"}
    if not key and not p["local"]:
        return {"ok": False, "error": "先填 API key"}
    if re.search(r"[\r\n]", key):
        return {"ok": False, "error": "API key 里有换行"}
    headers = {"User-Agent": "stardestroyer/0.1", "Accept": "application/json"}
    if pid.startswith("google"):
        headers["x-goog-api-key"] = key
    elif pid == "anthropic":
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
    elif key:
        headers["Authorization"] = f"Bearer {key}"
    last = ""
    for url in _urls(base):
        try:
            ids = _parse(net.request_json(url + ("?limit=1000" if pid == "anthropic" else "?pageSize=1000" if pid.startswith("google") else ""), headers=headers, timeout=20, attempts=2))
        except urllib.error.HTTPError as exc:
            last = {401: "key 无效或没有权限（401）", 403: "没有权限（403）", 404: "没有模型列表接口（404）"}.get(exc.code, f"HTTP {exc.code}")
            if exc.code in (401, 403):
                break  # the address is right, the key is not
            continue
        except (OSError, ValueError) as exc:
            last = str(getattr(exc, "reason", "") or exc)[:160]
            continue
        chat = [i for i in ids if not _NOT_CHAT.search(i)]
        if chat:
            known = {m["id"]: m for m in p["models"]}
            return {"ok": True, "url": url, "hidden": len(ids) - len(chat),
                    "models": [{"id": i, "name": known.get(i, {}).get("name", ""), "context": known.get(i, {}).get("context", 0)} for i in sorted(chat, key=str.lower)]}
        last = "列表是空的"
    return {"ok": False, "error": f"没有取到模型列表：{last}"}


def chosen() -> dict:
    pid = os.environ.get("LLM_PROVIDER") or OFFICIAL
    return {"id": pid, "model": os.environ.get("LLM_MODEL") or (DSH_DEFAULT if pid == OFFICIAL else ""),
            "base": os.environ.get("LLM_BASE_URL") or "", "key": os.environ.get(key_name(pid), "")}


def label() -> str:
    c = chosen()
    return f"{c['id']}/{c['model']}" if c["model"] else c["id"]


def why_not() -> str:
    c = chosen()
    extra = _EXTRA.get(c["id"])
    if not c["model"]:
        return f"{c['id']} 还没有选模型"
    base = c["base"] or (extra or {}).get("base", "")
    if extra and not base:
        return "自定义服务缺少接口地址"
    if base:
        if insecure(base):
            return "接口地址必须是 https（本机除外）：key 和源码会发过去"
    if c["key"] or (extra or {}).get("local"):
        return ""
    if extra or c["id"] == OFFICIAL:
        return f"{c['id']} 缺少 API key"
    known = next((p for p in catalog() if p["id"] == c["id"]), None)
    if known and any(os.environ.get(e) for e in known["env"]):
        return ""  # dsh discovers the provider's own variable
    return f"{c['id']} 缺少 API key"


def env() -> dict:
    c = chosen()
    if c["id"] == OFFICIAL:
        return {}  # DEEPSEEK_API_KEY is already in the environment
    return {KEY_ENV: c["key"] or "local"}


def overlay() -> list[dict]:
    c = chosen()
    route = {"id": "agent-default-model", "config": {"provider": c["id"], "model": c["model"]}}
    if c["id"] == OFFICIAL:
        return [route]
    p: dict = {}
    extra = _EXTRA.get(c["id"])
    if c["key"] or extra:
        p["apiKeyEnv"] = KEY_ENV
    if c["base"] or extra:
        p["baseURL"] = c["base"] or extra["base"]
    if extra:
        p.update(displayName=extra["name"], api="openai-completions", models=[{"id": c["model"]}])
    else:
        known = next((x for x in catalog() if x["id"] == c["id"]), None)
        if known and c["model"] not in {m["id"] for m in known["models"]}:
            p["models"] = [{"id": c["model"]}]  # newer than the installed catalog
    return [route, {"id": "llm-pi-ai", "config": {"providers": {c["id"]: p}}}]
