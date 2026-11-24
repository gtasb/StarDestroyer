"""Project profiling: what the target actually depends on, with evidence.

Rules are generated from these facts, never from a guess about the stack.
"""

import pathlib
import re

_BUILD_NAMES = ("pom.xml", "build.gradle", "build.gradle.kts",
                "requirements.txt", "pyproject.toml", "go.mod", "build.sbt")
_EXT = {".java": "java", ".kt": "java", ".py": "python", ".go": "go"}

# dependency token -> framework family used by the rule catalog
SIGNALS = {
    "spring-boot": "spring", "spring-web": "spring", "spring-webmvc": "spring",
    "spring-jdbc": "jdbc", "spring-boot-starter-jdbc": "jdbc", "jdbctemplate": "jdbc",
    "mybatis": "mybatis", "hibernate": "jpa", "spring-data-jpa": "jpa",
    "javax.persistence": "jpa", "jakarta.persistence": "jpa",
    "flask": "flask", "flask-sqlalchemy": "flask", "sqlalchemy": "sqlalchemy",
    "django": "django", "fastapi": "fastapi",
    "gin-gonic": "gin", "labstack/echo": "echo", "gorm.io": "gorm",
}


def _read(p: pathlib.Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _deps_from(path: pathlib.Path) -> list[str]:
    text = _read(path)
    name = path.name
    if name == "pom.xml":
        return [m.lower() for m in re.findall(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", text)]
    if name.startswith("build.gradle"):
        pairs = re.findall(r"""['"]([\w.\-]+):([\w.\-]+)""", text)
        return [f"{g}:{a}".lower() for g, a in pairs] + [a.lower() for _, a in pairs]
    if name == "requirements.txt":
        return [re.split(r"[=<>!~ ]", line.strip())[0].lower()
                for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if name == "pyproject.toml":
        return [m.lower() for m in re.findall(r'^\s*"([A-Za-z0-9_.\-]+)"', text, re.M)]
    if name == "go.mod":
        mods = re.findall(r"^\s*([\w.\-/]+)\s+v[\d.]", text, re.M)
        return [m.lower() for m in mods]
    return []


def profile(root: str) -> dict:
    p = pathlib.Path(root)
    if not p.exists():
        return {"ok": False, "error": f"路径不存在: {root}"}

    counts: dict[str, int] = {}
    build_files: list[pathlib.Path] = []
    seen_build: set[pathlib.Path] = set()
    # Build descriptors usually sit at the project root, while users point the
    # scan at src/. Look up to two levels above, but never count sources there.
    for anc in (p, p.parent, p.parent.parent):
        for name in _BUILD_NAMES:
            cand = anc / name
            if cand.is_file() and cand.resolve() not in seen_build:
                seen_build.add(cand.resolve())
                build_files.append(cand)

    for f in p.rglob("*"):
        if not f.is_file() or "/.work/" in f.as_posix():
            continue
        lang = _EXT.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    deps: list[str] = []
    evidence: dict[str, str] = {}
    for bf in build_files:
        for d in _deps_from(bf):
            deps.append(d)
            evidence.setdefault(d, bf.name)

    frameworks = sorted({SIGNALS[d] for d in deps if d in SIGNALS})
    # Source-level hints when no build file exists.
    blob = " ".join(_read(f)[:4000] for f in list(p.rglob("*.java"))[:200])
    for token, fam in (("javax.persistence", "jpa"), ("jakarta.persistence", "jpa"),
                       ("java.sql.Statement", "jdbc"), ("flask", "flask"),
                       ("django", "django"), ("gin-gonic", "gin")):
        if token in blob and fam not in frameworks:
            frameworks.append(fam)

    primary = max(counts, key=counts.get) if counts else "unknown"
    return {
        "ok": True,
        "root": str(p),
        "language": primary,
        "file_counts": counts,
        "build_files": [b.name for b in build_files],
        "dependencies": sorted(set(deps)),
        "frameworks": sorted(set(frameworks)),
        "evidence": evidence,
    }
