"""Endpoint extraction and capability inference.

Endpoints are what makes an n-day reachable: a vulnerable library matters more
when the endpoint in front of it is a file upload than when it is a health check.
"""

import pathlib
import re

JAVA = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
PY = re.compile(r'@(?:app|router|bp)\.(get|post|put|delete|patch|route)\s*\(\s*["\']([^"\']+)["\']')
GO = re.compile(r'\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"')

_EXTS = {".java": JAVA, ".py": PY, ".go": GO}

CAPABILITIES = [
    ("admin", "管理后台"), ("upload", "文件上传"), ("download", "文件下载"),
    ("export", "数据导出"), ("import", "数据导入"), ("login", "认证"),
    ("auth", "认证"), ("payment", "支付"), ("order", "订单"),
    ("user", "用户管理"), ("exec", "命令执行面"), ("debug", "调试接口"),
    ("preview", "预览/渲染"), ("proxy", "代理/转发"), ("url", "外链访问"),
    ("sql", "数据查询"), ("api", "开放接口"),
]


def infer_features(path: str) -> list[str]:
    low = path.lower()
    return [label for token, label in CAPABILITIES if token in low]


def extract(root: str, limit_files: int = 4000) -> list[dict]:
    p = pathlib.Path(root)
    if not p.exists():
        return []
    out, seen = [], 0
    for f in p.rglob("*"):
        ext = f.suffix.lower()
        if ext not in _EXTS or not f.is_file():
            continue
        seen += 1
        if seen > limit_files:
            break
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _EXTS[ext].finditer(line):
                method = m.group(1).upper()
                if method == "REQUEST":
                    method = "ANY"
                route = m.group(2)
                out.append({
                    "method": method,
                    "path": route,
                    "file": f.relative_to(p).as_posix(),
                    "line": i,
                    "features": infer_features(route),
                })
    return out
