"""DeepSeek judge.

The LLM explains a verdict, it never produces one. verdict.judge() already ran;
this module only writes prose around evidence that already exists, and its
system prompt forbids inventing files, lines or call relationships.
"""

import json
import os
import urllib.error
import urllib.request

BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
KEY = os.environ.get("DEEPSEEK_API_KEY", "")

SYSTEM = (
    "你是源码审计报告的撰写者。给你的是两个静态分析引擎已经产出的证据。"
    "规则：1) 只能引用证据中出现的文件名、行号、函数名；2) 缺失即写「证据不足」，禁止推测补全；"
    "3) 若证据标注 needs_review/needs_dynamic，必须写明尚缺什么；4) 不复述工具命令行。"
)


def available() -> bool:
    return bool(KEY)


def chat(system: str, user: str, max_chars: int = 12000) -> dict:
    """Single-turn call. Callers enforce their own output contract."""
    if not KEY:
        return {"ok": False, "error": "DEEPSEEK_API_KEY 未设置"}
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user[:max_chars]},
        ],
        "temperature": 0.1,
        "stream": False,
    }
    req = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read())
        return {"ok": True, "text": body["choices"][0]["message"]["content"], "model": MODEL}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"HTTP {exc.code}", "detail": exc.read()[:500].decode(errors="replace")}
    except Exception as exc:  # network/JSON
        return {"ok": False, "error": str(exc)}


def explain(evidence: dict, question: str = "用中文简述这条链的利用条件与验证缺口。") -> dict:
    return chat(SYSTEM, question + "\n\n证据(JSON):\n" + json.dumps(evidence, ensure_ascii=False))
