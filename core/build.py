"""Compile a Java project so the call-graph engine has bytecode to read.

Building runs the project's own build scripts and plugins, which is the same as
running its code. It is therefore opt-in per project. The build happens on a copy,
so the audited tree stays as it was, and without our credentials in the environment.
That is hygiene, not a sandbox.
"""

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import zipfile

from . import logging, proc, projects, store

WORK = pathlib.Path(__file__).resolve().parents[1] / ".work" / "builds"
TIMEOUT_S = 1800
_NEVER = {".git", ".svn", "node_modules", ".idea", ".gradle", ".work"}
_OUTPUT = {"target": ("pom.xml",), "build": ("build.gradle", "build.gradle.kts")}
_MAVEN, _GRADLE = ("pom.xml",), ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
# Everything else stays out, our API keys in particular.
_ENV = {"path", "pathext", "systemroot", "systemdrive", "windir", "comspec", "temp", "tmp", "tmpdir", "userprofile", "home",
        "homedrive", "homepath", "appdata", "localappdata", "programdata", "programfiles", "programfiles(x86)", "programw6432",
        "java_home", "m2_home", "maven_home", "maven_opts", "gradle_home", "gradle_user_home", "gradle_opts", "lang", "lc_all",
        "http_proxy", "https_proxy", "no_proxy", "number_of_processors", "processor_architecture", "os", "username", "user"}
_MVN_ARGS = ["-B", "-ntp", "-fae", "package", "-Dmaven.test.skip=true", "-Dmaven.javadoc.skip=true", "-Dmaven.source.skip=true",
             "-Dcheckstyle.skip=true", "-Dpmd.skip=true", "-Dspotbugs.skip=true", "-Denforcer.skip=true", "-Dgpg.skip=true",
             "-Dskip.npm=true", "-Dskip.yarn=true"]
_GRADLE_ARGS = ["--no-daemon", "--console=plain", "--continue", "assemble"]


def roots(path: str) -> list[tuple[pathlib.Path, str]]:
    """Topmost directories that can be built, with the tool each one needs."""
    base, out = pathlib.Path(path).resolve(), []
    for d, dirs, files in os.walk(base):
        kind = "maven" if set(files) & set(_MAVEN) else "gradle" if set(files) & set(_GRADLE) else ""
        if kind:
            out.append((pathlib.Path(d), kind))
            dirs[:] = []
        else:
            dirs[:] = [x for x in dirs if x not in _NEVER]
    return out


def _ignored(d: str, names: list[str]) -> set[str]:
    return {n for n in names if n in _NEVER or any(x in names for x in _OUTPUT.get(n, ()))}


def _files(base: pathlib.Path):
    for d, dirs, files in os.walk(base):
        skip = _ignored(d, dirs + files)
        dirs[:] = sorted(x for x in dirs if x not in skip)
        for f in sorted(files):
            yield pathlib.Path(d) / f


def _key(base: pathlib.Path) -> str:
    h = hashlib.sha256(os.environ.get("BUILD_JAVA_HOME", "").encode())
    for f in _files(base):
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f.relative_to(base).as_posix()}\0{st.st_size}\0{st.st_mtime_ns}\0".encode())
    return h.hexdigest()[:16]


def environment() -> dict:
    env = {k: v for k, v in os.environ.items() if k.lower() in _ENV}
    home = os.environ.get("BUILD_JAVA_HOME")
    if home:
        env["JAVA_HOME"] = home
        path = next((k for k in env if k.lower() == "path"), "PATH")
        env[path] = str(pathlib.Path(home) / "bin") + os.pathsep + env.get(path, "")
    # cmd.exe looks in the current directory, the project's, before PATH.
    return {**env, "NoDefaultCurrentDirectoryInExePath": "1"}


def _command(root: pathlib.Path, kind: str) -> list[str] | None:
    """The machine's own tool; a project's Gradle wrapper only when there is none."""
    if kind == "maven":
        exe = shutil.which("mvn")
        return [exe, *_MVN_ARGS] if exe else None
    exe = shutil.which("gradle")
    if not exe:
        wrapper = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
        exe = str(wrapper) if wrapper.is_file() else None
    return [exe, *_GRADLE_ARGS] if exe else None


def why_not(path: str) -> str:
    found = roots(path)
    if not found:
        return "没有找到 pom.xml 或 build.gradle，无法自动编译"
    for root, kind in found:
        if not _command(root, kind):
            return f"需要 {'Maven（mvn）' if kind == 'maven' else 'Gradle'}，PATH 里没有找到"
    return ""


def _fat(p: pathlib.Path) -> bool:
    try:
        with zipfile.ZipFile(p) as z:
            return any(n.startswith(("BOOT-INF/", "WEB-INF/")) for n in z.namelist())
    except (OSError, zipfile.BadZipFile):
        return False


def _has_classes(p: pathlib.Path) -> bool:
    try:
        with zipfile.ZipFile(p) as z:
            return any(n.endswith(".class") for n in z.namelist())
    except (OSError, zipfile.BadZipFile):
        return False


def artifacts(base: pathlib.Path) -> list[pathlib.Path]:
    out = []
    for p in base.rglob("*"):
        if p.suffix in (".jar", ".war") and (p.parent.name == "target" or p.parent.parts[-2:] == ("build", "libs")):
            if not re.search(r"-(sources|javadoc|tests?|plain)\.jar$", p.name) and not p.name.startswith("original-") and _has_classes(p):
                out.append(p)
    return sorted(out)


def _errors(text: str) -> list[str]:
    lines = [x.strip() for x in text.splitlines()]
    hits = [x for x in lines if re.match(r"\[ERROR\]|e: |error:|.*\.java:\d+: error|FAILURE:|\* What went wrong|Execution failed|> ", x) and len(x) > 10]
    hits = [x for x in hits if "Some problems were encountered" not in x and "Re-run Maven" not in x and "[Help 1]" not in x[-12:]] or hits
    return list(dict.fromkeys(hits or [x for x in lines if x][-8:]))[:8]


def run(path: str) -> dict:
    """{ok, target, jars, notes} -- target is what the call-graph engine should read."""
    base = pathlib.Path(path).resolve()
    if not base.is_dir():
        return {"ok": False, "error": f"不是目录: {path}"}
    why = why_not(str(base))
    if why:
        return {"ok": False, "error": why}
    work = WORK / projects.project_id(str(base))
    with store.lock(work / "build"):
        key, state = _key(base), work / "build.json"
        done = store.read(state, {})
        if done.get("key") == key and pathlib.Path(done.get("target", "")).exists():
            logging.info("build", "reused", path=str(base), target=done["target"])
            return {"ok": True, "reused": True, **done}
        return _run(base, work, state, key)


def _run(base: pathlib.Path, work: pathlib.Path, state: pathlib.Path, key: str) -> dict:
    state.unlink(missing_ok=True)
    src, out = work / "src", work / "out"
    for d in (src, out):
        shutil.rmtree(d, ignore_errors=True)
    proc.stage("复制源码到编译目录")
    shutil.copytree(base, src, symlinks=True, ignore=_ignored, dirs_exist_ok=True)
    notes, tails = [], []
    for root, kind in roots(str(src)):
        rel = root.relative_to(src).as_posix()
        argv = _command(root, kind)
        proc.stage(f"编译 {rel if rel != '.' else base.name}（{kind}）")
        logging.info("build", "start", path=str(base), module=rel, tool=argv[0])
        try:
            r = proc.run(argv, timeout=TIMEOUT_S, cwd=str(root), env=environment())
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"编译超时（{TIMEOUT_S}s）"}
        except OSError as exc:
            return {"ok": False, "error": f"编译启动失败: {exc}"}
        (work / "build.log").write_text(r.stdout + "\n" + r.stderr, encoding="utf-8")
        if r.returncode:
            tails += _errors(r.stdout + "\n" + r.stderr)
            notes.append(f"{rel if rel != '.' else base.name} 没有完整编译通过，调用图只含编译成功的模块")
        logging.info("build", "end", module=rel, exit=r.returncode)
    jars = artifacts(src)
    if not jars:
        return {"ok": False, "error": "编译没有产出 jar" + (f"：{tails[0][:200]}" if tails else ""), "tail": tails, "log": str(work / "build.log")}
    fat = [j for j in jars if _fat(j)]
    if not fat:
        notes.append("没有可执行 jar，第三方依赖不在调用图里，跨到依赖的链查不到")
    out.mkdir(parents=True)
    kept = []
    for i, j in enumerate(fat or jars):
        to = out / (j.name if not (out / j.name).exists() else f"{i}-{j.name}")
        shutil.copy2(j, to)
        kept.append(to)
    shutil.rmtree(src, ignore_errors=True)
    got = {"key": key, "target": str(kept[0] if len(kept) == 1 else out), "jars": [k.name for k in kept], "notes": notes, "tail": tails}
    # A build with failed modules is not reused: the next try may have what was missing.
    if not tails:
        store.write(state, got)
    return {"ok": True, "reused": False, **got}
