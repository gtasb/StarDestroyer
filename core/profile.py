"""Project profiling: what the target actually depends on, with evidence.

Rules are generated from these facts, never from a guess about the stack.
"""

import json
import os
import pathlib
import re
import tomllib

_BUILD_NAMES = ("pom.xml", "build.gradle", "build.gradle.kts",
                "requirements.txt", "pyproject.toml", "go.mod", "build.sbt", "package.json", "composer.json")
_EXT = {".java": "java", ".kt": "java", ".py": "python", ".go": "go",
        **dict.fromkeys((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"), "js"),
        **dict.fromkeys((".php", ".phtml", ".php5", ".php7"), "php")}
BUILT = re.compile(r"\.(min|bundle|chunk)\.js$|\.d\.ts$", re.I)  # generated, not written

# (pattern over a normalised dependency name, framework family). Names come as
# artifact ids, group:artifact, module paths -- so match parts, not whole strings.
SIGNALS = [
    (r"spring-(boot|web|webmvc|webflux)\b", "spring"),
    (r"spring(-boot-starter)?-jdbc\b|jdbctemplate", "jdbc"),
    (r"mybatis", "mybatis"),
    (r"hibernate-(core|orm|entitymanager)|data-jpa|(javax|jakarta)\.persistence", "jpa"),
    (r"^flask\b", "flask"), (r"sqlalchemy", "sqlalchemy"), (r"^django\b", "django"),
    (r"^fastapi\b", "fastapi"), (r"gin-gonic/gin\b", "gin"), (r"labstack/echo\b", "echo"),
    (r"gofiber/fiber\b", "fiber"), (r"gorm\.io/gorm\b|jinzhu/gorm\b", "gorm"),
    (r"^express$", "express"), (r"^koa$", "koa"), (r"^fastify$", "fastify"), (r"^@nestjs/core$", "nestjs"), (r"^next$", "next"),
    (r"^nuxt$", "nuxt"), (r"^vue$", "vue"), (r"^react$", "react"), (r"^@angular/core$", "angular"), (r"^svelte$", "svelte"),
    (r"^laravel/(framework|lumen-framework)$", "laravel"), (r"^topthink/(framework|think)$", "thinkphp"), (r"^symfony/(framework-bundle|http-kernel)$", "symfony"),
    (r"^yiisoft/yii2?$", "yii"), (r"^codeigniter4?/framework$|^codeigniter/framework$", "codeigniter"), (r"^cakephp/cakephp$", "cakephp"), (r"^doctrine/orm$", "doctrine"),
    (r"^electron$", "electron"), (r"^sequelize$", "sequelize"), (r"^mongoose$", "mongoose"), (r"^knex$", "knex"),
]
SKIP_DIRS = {".git", ".work", "node_modules", "target", "build", "dist", "venv", ".venv",
             "__pycache__", ".idea", ".gradle"}
MAX_BUILD_FILES = 200


def _read(p: pathlib.Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _deps_from(path: pathlib.Path) -> list[str]:
    text = _read(path)
    name = path.name
    if name == "pom.xml":
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        return [m.lower() for m in re.findall(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", text)]
    if name.startswith("build.gradle"):
        pairs = re.findall(r"""['"]([\w.\-]+):([\w.\-]+)""", text)
        return [f"{g}:{a}".lower() for g, a in pairs] + [a.lower() for _, a in pairs]
    if name.startswith("requirements") and name.endswith(".txt"):
        return [n for n in (_py_name(line) for line in text.splitlines()) if n]
    if name == "pyproject.toml":
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return []
        project = doc.get("project", {})
        specs = list(project.get("dependencies", []))
        for extra in project.get("optional-dependencies", {}).values():
            specs += extra
        specs += list(doc.get("tool", {}).get("poetry", {}).get("dependencies", {}))
        return [n for n in map(_py_name, specs) if n and n != "python"]
    if name == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        return [d.lower() for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
                for d in (doc.get(k) if isinstance(doc, dict) and isinstance(doc.get(k), dict) else {})]
    if name == "composer.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        return [d.lower() for k in ("require", "require-dev") for d in (doc.get(k) if isinstance(doc, dict) and isinstance(doc.get(k), dict) else {}) if "/" in d]
    if name == "go.mod":
        return [m.lower() for m in
                re.findall(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[\w.\-/]+)\s+v\d", text, re.M)]
    return []


def _py_name(spec: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", spec)
    return m.group(1).lower() if m else ""


def _walk(root: pathlib.Path):
    """Files under root, without descending into build output and caches."""
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            yield pathlib.Path(base) / f


def profile(root: str) -> dict:
    p = pathlib.Path(root)
    if not p.exists():
        return {"ok": False, "error": f"路径不存在: {root}"}

    counts: dict[str, int] = {}
    build_files: list[pathlib.Path] = []
    java: list[pathlib.Path] = []
    for f in _walk(p):
        if f.name in _BUILD_NAMES and len(build_files) < MAX_BUILD_FILES:
            build_files.append(f)
        lang = None if BUILT.search(f.name) else _EXT.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
        if f.suffix == ".java" and len(java) < 200:
            java.append(f)
    # Users point the scan at src/: the descriptor is then above it. The nearest
    # directory that has one wins; anything further up belongs to someone else.
    if not build_files:
        for anc in (p.parent, p.parent.parent):
            build_files = [anc / n for n in _BUILD_NAMES if (anc / n).is_file()]
            if build_files:
                break

    deps: list[str] = []
    evidence: dict[str, str] = {}
    for bf in build_files:
        for d in _deps_from(bf):
            deps.append(d)
            evidence.setdefault(d, bf.name)

    found: dict[str, list[str]] = {}
    for d in sorted(set(deps)):
        for rx, fam in SIGNALS:
            if re.search(rx, d):
                found.setdefault(fam, []).append(d)
    # Source-level hints when no build file exists.
    blob = " ".join(_read(f)[:4000] for f in java)
    for token, fam in (("javax.persistence", "jpa"), ("jakarta.persistence", "jpa"),
                       ("org.springframework.jdbc", "jdbc"), ("org.apache.ibatis", "mybatis"),
                       ("com.baomidou.mybatisplus", "mybatis")):
        if token in blob:
            found.setdefault(fam, []).append(f"import {token}")

    primary = max(counts, key=counts.get) if counts else "unknown"
    return {
        "ok": True,
        "root": str(p),
        "language": primary,
        "file_counts": counts,
        "build_files": [b.relative_to(p).as_posix() if b.is_relative_to(p) else str(b) for b in build_files],
        "dependencies": sorted(set(deps)),
        "frameworks": sorted(found),
        "framework_evidence": found,
        "evidence": evidence,
    }
