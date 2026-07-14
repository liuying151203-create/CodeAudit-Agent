from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.schemas.enums import ProfileScope
from app.schemas.project import ProjectProfile

IGNORED_DIRS = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
DEPENDENCY_FILES = {
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "pipfile",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
}
PROFILE_SUFFIXES = {".gradle", ".java", ".json", ".properties", ".py", ".toml", ".xml", ".yaml", ".yml"}
MAX_PROFILE_FILES = 1500
MAX_FILE_BYTES = 512_000
MAX_TEXT_CHARS = 40_000


def build_project_profile(repo_path: str | None, source_files: list[dict[str, Any]]) -> ProjectProfile:
    root = _valid_root(repo_path)
    project_paths = _collect_project_paths(root) if root else []
    if root:
        rel_paths = [path.relative_to(root).as_posix() for path in project_paths]
        text_by_path = _read_repository_text(root, project_paths)
    else:
        rel_paths = [str(item.get("path", "")).replace("\\", "/") for item in source_files]
        text_by_path = {
            str(item.get("path", "")).replace("\\", "/"): str(item.get("content", ""))[:MAX_TEXT_CHARS]
            for item in source_files
        }

    dependency_files = sorted(path for path in rel_paths if Path(path).name.lower() in DEPENDENCY_FILES)
    languages = _detect_languages(rel_paths, dependency_files)
    frameworks = _detect_frameworks(rel_paths, text_by_path)
    entrypoints = _detect_entrypoints(rel_paths, text_by_path)
    route_files = _classify_files(rel_paths, text_by_path, _ROUTE_PATH_MARKERS, _ROUTE_CONTENT_MARKERS)
    auth_files = _classify_files(rel_paths, text_by_path, _AUTH_PATH_MARKERS, _AUTH_CONTENT_MARKERS)
    db_files = _classify_files(rel_paths, text_by_path, _DB_PATH_MARKERS, _DB_CONTENT_MARKERS)
    upload_files = _classify_files(rel_paths, text_by_path, _UPLOAD_PATH_MARKERS, _UPLOAD_CONTENT_MARKERS)
    security_signals = _detect_security_signals(text_by_path)
    risk_surfaces = _infer_risk_surfaces(
        dependency_files=dependency_files,
        route_files=route_files,
        auth_files=auth_files,
        db_files=db_files,
        upload_files=upload_files,
        security_signals=security_signals,
    )
    profile_scope, confidence, missing_context = _profile_completeness(root, source_files, dependency_files, languages)

    return ProjectProfile(
        languages=languages,
        frameworks=frameworks,
        dependency_files=dependency_files,
        entrypoints=entrypoints,
        route_files=route_files,
        auth_files=auth_files,
        db_files=db_files,
        upload_files=upload_files,
        risk_surfaces=risk_surfaces,
        security_signals=security_signals,
        profile_scope=profile_scope,
        profile_confidence=confidence,
        missing_context=missing_context,
    )


def _valid_root(repo_path: str | None) -> Path | None:
    if not repo_path:
        return None
    root = Path(repo_path).resolve()
    return root if root.exists() and root.is_dir() else None


def _collect_project_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        if len(paths) >= MAX_PROFILE_FILES:
            break
        if not path.is_file() or path.is_symlink() or _is_ignored(path, root):
            continue
        if path.name.lower() not in DEPENDENCY_FILES and path.suffix.lower() not in PROFILE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        paths.append(path)
    return sorted(paths)


def _is_ignored(path: Path, root: Path) -> bool:
    return bool(set(path.relative_to(root).parts) & IGNORED_DIRS)


def _read_repository_text(root: Path, paths: list[Path]) -> dict[str, str]:
    text_by_path: dict[str, str] = {}
    for path in paths:
        rel_path = path.relative_to(root).as_posix()
        try:
            text_by_path[rel_path] = path.read_text(encoding="utf-8", errors="ignore")[:MAX_TEXT_CHARS]
        except OSError:
            continue
    return text_by_path


def _detect_languages(paths: list[str], dependency_files: list[str]) -> list[str]:
    languages: set[str] = set()
    suffixes = {Path(path).suffix.lower() for path in paths}
    dependency_names = {Path(path).name.lower() for path in dependency_files}
    if ".py" in suffixes or dependency_names & {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock"}:
        languages.add("Python")
    if ".java" in suffixes or dependency_names & {"pom.xml", "build.gradle", "build.gradle.kts"}:
        languages.add("Java")
    return sorted(languages)


def _detect_frameworks(paths: list[str], text_by_path: dict[str, str]) -> list[str]:
    joined = "\n".join(text_by_path.values()).lower()
    names = {Path(path).name.lower() for path in paths}
    frameworks: set[str] = set()
    checks = {
        "FastAPI": ("fastapi", "apirouter", "fastapi("),
        "Flask": ("from flask", "import flask", "flask("),
        "Django": ("django", "django.conf", "django.urls"),
        "SQLAlchemy": ("sqlalchemy",),
        "Spring Boot": ("spring-boot", "@springbootapplication"),
        "Spring MVC": ("@restcontroller", "@controller", "@requestmapping"),
        "Spring Security": ("spring-security", "securityfilterchain", "@preauthorize"),
        "MyBatis": ("mybatis", "@mapper", "<mapper"),
    }
    for framework, markers in checks.items():
        if any(marker in joined for marker in markers):
            frameworks.add(framework)
    if "manage.py" in names:
        frameworks.add("Django")
    return sorted(frameworks)


def _detect_entrypoints(paths: list[str], text_by_path: dict[str, str]) -> list[str]:
    entrypoint_names = {"app.py", "asgi.py", "main.py", "manage.py", "server.py", "wsgi.py"}
    entrypoints = {path for path in paths if Path(path).name.lower() in entrypoint_names}
    for path, content in text_by_path.items():
        lowered = content.lower()
        if "@springbootapplication" in lowered or re.search(r"\b(fastapi|flask)\s*\(", lowered):
            entrypoints.add(path)
    return sorted(entrypoints)


def _classify_files(
    paths: list[str],
    text_by_path: dict[str, str],
    path_markers: tuple[str, ...],
    content_markers: tuple[str, ...],
) -> list[str]:
    matches: set[str] = set()
    for path in paths:
        if Path(path).name.lower() in DEPENDENCY_FILES:
            continue
        normalized_path = path.lower().replace("\\", "/")
        content = text_by_path.get(path, "").lower()
        if any(marker in normalized_path for marker in path_markers) or any(marker in content for marker in content_markers):
            matches.add(path)
    return sorted(matches)


def _detect_security_signals(text_by_path: dict[str, str]) -> list[str]:
    joined = "\n".join(text_by_path.values()).lower()
    signals: set[str] = set()
    checks = {
        "command_execution_api": ("os.system(", "subprocess.", "runtime.getruntime().exec", "processbuilder("),
        "unsafe_deserialization_api": ("pickle.load", "pickle.loads", "yaml.load", "objectinputstream", "readobject("),
        "dynamic_sql_construction": ("cursor.execute", "${", "statement.execute", "createquery("),
        "secret_like_identifier": ("api_key", "apikey", "client_secret", "password =", "token ="),
        "filesystem_input": ("uploadfile", "multipartfile", "send_file", "../", "..\\"),
    }
    for signal, markers in checks.items():
        if any(marker in joined for marker in markers):
            signals.add(signal)
    return sorted(signals)


def _infer_risk_surfaces(
    dependency_files: list[str],
    route_files: list[str],
    auth_files: list[str],
    db_files: list[str],
    upload_files: list[str],
    security_signals: list[str],
) -> list[str]:
    signals = set(security_signals)
    surfaces: set[str] = {"Secrets"}
    if db_files or "dynamic_sql_construction" in signals:
        surfaces.add("SQL Injection")
    if "command_execution_api" in signals:
        surfaces.add("Command Execution")
    if upload_files or "filesystem_input" in signals:
        surfaces.add("Path Traversal")
    if "unsafe_deserialization_api" in signals:
        surfaces.add("Unsafe Deserialization")
    if route_files or auth_files:
        surfaces.add("Broken Access Control")
    if dependency_files:
        surfaces.add("Dependency Risk")
    return sorted(surfaces)


def _profile_completeness(
    root: Path | None,
    source_files: list[dict[str, Any]],
    dependency_files: list[str],
    languages: list[str],
) -> tuple[ProfileScope, float, list[str]]:
    is_diff = any(item.get("source") == "diff" for item in source_files)
    if is_diff and root:
        missing = [] if dependency_files else ["No dependency file was found while enriching the diff profile."]
        return ProfileScope.DIFF_ENRICHED, 0.85 if dependency_files else 0.75, missing
    if is_diff:
        confidence = 0.6 if languages else 0.4
        return (
            ProfileScope.DIFF_ONLY,
            confidence,
            ["Repository files, dependency metadata, and cross-file call context are unavailable."],
        )
    missing = [] if dependency_files else ["No supported dependency file was found."]
    return ProfileScope.FULL_REPO, 1.0 if dependency_files else 0.9, missing


_ROUTE_PATH_MARKERS = ("api/", "controller/", "controllers/", "/route", "/router", "urls.py")
_ROUTE_CONTENT_MARKERS = (
    "@app.route",
    "@app.get",
    "@app.post",
    "apirouter(",
    "@restcontroller",
    "@controller",
    "@requestmapping",
    "@getmapping",
    "@postmapping",
)
_AUTH_PATH_MARKERS = ("auth/", "security/", "jwt", "login", "permission")
_AUTH_CONTENT_MARKERS = (
    "oauth2",
    "jwt",
    "securityfilterchain",
    "@preauthorize",
    "@secured",
    "permission_required",
    "login_required",
)
_DB_PATH_MARKERS = ("dao/", "db/", "mapper/", "/model", "repository/")
_DB_CONTENT_MARKERS = (
    "sqlalchemy",
    "sqlite3",
    "cursor.execute",
    "jdbctemplate",
    "@mapper",
    "@repository",
    "<mapper",
    "select ",
)
_UPLOAD_PATH_MARKERS = ("/file", "/upload", "attachment", "filecontroller", "upload/")
_UPLOAD_CONTENT_MARKERS = ("uploadfile", "multipartfile", "multipart/form-data", "send_file", "transferto(")
