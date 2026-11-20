"""Redacted static checks for public source and explicitly selected reports."""

from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import tomllib
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

MAX_TREE_ENTRIES = 4096
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 80 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_REPORTS = 64

_PRIVATE_NAMES = frozenset({"groundtruth", "groundtruthexhibit", "hercules", "mobipute", "truthpute"})
_PRIVATE_DIRECTORIES = _PRIVATE_NAMES | {"private", "secrets", "credentials", "privatedeployment"}
_PRIVATE_EXTENSIONS = frozenset({".key", ".pem", ".pfx", ".p12", ".kdbx"})
_DEPENDENCY_FILES = frozenset({
    "cargo.lock", "cargo.toml", "gemfile", "go.mod", "package.json", "package-lock.json",
    "pipfile", "pipfile.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "yarn.lock",
})
_APPROVED_ACTIONS = frozenset({
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
})
_APPROVED_PIP_FLAGS = frozenset({
    "--disable-pip-version-check", "--no-cache-dir", "--no-deps", "--only-binary=:all:",
})
_APPROVED_PIP_PREFIXES = (
    ("python", "-m"), ("python3", "-m"), ("python", "-I", "-m"),
)
_APPROVED_LOCK_PATH = (".github", "qualification-requirements.txt")
_BUILDER_LOCK_PATH = (".github", "product-builder.lock")
_BUILDER_LOCK_LINE = "setuptools==84.2.1 --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"
_APPROVED_LOCK_LINE = (
    "PyYAML==6.0.3 --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc"
)
_APPROVED_LOCK_INSTALL = (
    "python", "-I", "-m", "pip", "--isolated", "install", "--no-cache-dir", "--no-deps",
    "--only-binary=:all:", "--require-hashes", "--index-url", "https://pypi.org/simple",
    "-r", "/".join(_APPROVED_LOCK_PATH),
)
_SOURCE_IMAGE_SIGNATURES = {
    ".png": (b"\x89PNG\r\n\x1a\n",), ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",), ".webp": (b"RIFF",),
}
_REPORT_TYPES = frozenset({".json", ".jsonl", ".md", ".sarif", ".txt"})
_PRIVATE_REPORT_FIELDS = frozenset({
    "accesstoken", "clientsecret", "credentialvalue", "privatekey", "rawsecret",
    "rawtenantid", "rawtenantrecord", "refreshtoken",
})
_REDACTED_FIELD_VALUES = (None, "", "[REDACTED]", "<redacted>")
_SECRET_PATTERN = re.compile(
    r"(?<![\w-])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r"|(?:sk_live_|rk_live_)[A-Za-z0-9]{16,})(?![\w-])"
)
_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_PUBLIC_EMAIL_DOMAINS = frozenset({
    "example.com", "example.net", "example.org", "noreply.github.com", "users.noreply.github.com",
})
_PUBLIC_EMAIL_ADDRESSES = frozenset({"noreply@github.com"})
_PERSONAL_PATH = re.compile(r"(?i)(?:/(?:home|Users)/[^/\s]+/|[A-Z]:[\\/]Users[\\/][^\\/\s]+)")
_INSTALL_COMMAND = re.compile(
    r"\b(?:pip\d*(?:\s+--isolated)?\s+install|(?:npm|pnpm|yarn|uv)\s+(?:add|install|sync|ci))\b"
)
_JS_IMPORT = re.compile(
    r"""\b(?:from\s+|import\s+|(?:import|require)\s*\(\s*)['"]([^'"]+)['"]"""
)
_JS_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_HEX_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class GuardInputError(ValueError):
    """An input could not be evaluated within the publication policy."""


@dataclass
class GuardScan:
    """Accumulate fixed policy labels. Paths and input values stay in memory."""

    commit: str | None = None
    tree: str | None = None
    source_entries: int = 0
    report_entries: int = 0
    signals: Counter[str] = field(default_factory=Counter)
    unknown: Counter[str] = field(default_factory=Counter)

    def result(self, workflow_dependencies: bool) -> dict[str, object]:
        return {
            "schema": "wolftrap.public-guard.v1",
            "status": (
                "INCONCLUSIVE" if self.unknown
                else "STATIC REVIEW SIGNAL" if self.signals
                else "NO_PATTERN_MATCH"
            ),
            "source_commit": self.commit,
            "source_tree": self.tree,
            "source_entries": self.source_entries,
            "report_entries": self.report_entries,
            "workflow_dependencies_checked": workflow_dependencies,
            "environment": {
                "python": platform.python_version(),
                "system": platform.system(),
            },
            "limits": {
                "source_entries": MAX_TREE_ENTRIES,
                "source_bytes_per_entry": MAX_SOURCE_BYTES,
                "source_bytes_total": MAX_TOTAL_SOURCE_BYTES,
                "report_entries": MAX_REPORTS,
                "report_bytes_per_entry": MAX_REPORT_BYTES,
            },
            "signals": dict(sorted(self.signals.items())),
            "unknown": dict(sorted(self.unknown.items())),
        }


def _git(root: Path, *args: str) -> bytes:
    # Explicitly opt out of object replacement and partial-clone network fetches.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    try:
        process = subprocess.run(
            ["git", *args], cwd=root, env=env, check=False, timeout=15,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardInputError from exc
    if process.returncode:
        raise GuardInputError
    return process.stdout


def _git_object(root: Path, expression: str) -> str:
    result = _git(root, "rev-parse", "--verify", "--end-of-options", expression).decode("ascii").strip()
    if not _HEX_OBJECT_ID.fullmatch(result):
        raise GuardInputError
    return result


def _normalize(value: str) -> str:
    return "".join(char for char in unicodedata.normalize("NFKC", value).casefold() if char.isalnum())


def _path_parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    if (
        any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts)
        or any(unicodedata.normalize("NFKC", part).casefold() == ".git" for part in parts)
        or any(char in value for char in "\\:")
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise GuardInputError
    return parts


def _content_signals(text: str) -> set[str]:
    signals = set()
    if _SECRET_PATTERN.search(text):
        signals.add("credential-shape")
    if any(
        match[1].casefold() not in _PUBLIC_EMAIL_DOMAINS
        and match[0].casefold() not in _PUBLIC_EMAIL_ADDRESSES
        for match in _EMAIL_PATTERN.finditer(text)
    ):
        signals.add("contact-address")
    return signals


def _path_signals(parts: tuple[str, ...]) -> set[str]:
    name = parts[-1]
    basename = name.lower()
    file = PurePosixPath(name)
    suffix = file.suffix.lower()
    stem = _normalize(file.stem)
    signals = _content_signals("/".join(parts))
    if (
        any(_normalize(part) in _PRIVATE_DIRECTORIES for part in parts[:-1])
        or _normalize(name) in _PRIVATE_DIRECTORIES
        or (suffix in _JS_SUFFIXES | {".py"} and stem in _PRIVATE_NAMES)
        or (suffix in {".env", ".json", ".toml", ".yaml", ".yml"} and stem in _PRIVATE_DIRECTORIES)
        or basename in {".env", ".netrc", ".npmrc", ".git-credentials", ".gitmodules"}
        or basename.startswith(".env.")
        or suffix in _PRIVATE_EXTENSIONS
    ):
        signals.add("private-path")
    return signals


def _has_private_module(module: str) -> bool:
    return any(_normalize(part) in _PRIVATE_NAMES for part in re.split(r"[./]", module))


def _python_import_signals(source: str) -> set[str]:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [alias.name for alias in node.names]
            if node.module is not None:
                modules.append(node.module)
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            name = function.id if isinstance(function, ast.Name) else (
                function.attr if isinstance(function, ast.Attribute) else None
            )
            module = node.args[0]
            if name in {"__import__", "import_module"} and isinstance(module, ast.Constant):
                if isinstance(module.value, str):
                    modules = [module.value]
        if any(_has_private_module(module) for module in modules):
            return {"private-import"}
    return set()


def _project_dependency_signals(source: str) -> set[str]:
    document = tomllib.loads(source)
    build = document.get("build-system", {})
    project = document.get("project", {})
    if not isinstance(build, dict) or not isinstance(project, dict):
        raise GuardInputError
    optional = project.get("optional-dependencies", {})
    dynamic = project.get("dynamic", [])
    if not isinstance(optional, dict) or not isinstance(dynamic, list):
        raise GuardInputError
    approved_optional = {"build-scan": ["PyYAML>=6.0.1,<7"]}
    if (
        project.get("dependencies", []) != []
        or any(item in ("dependencies", "optional-dependencies") for item in dynamic)
        or any(group not in approved_optional or requirements != approved_optional[group]
               for group, requirements in optional.items())
        or build.get("requires", []) not in ([], ["setuptools>=68"])
        or build.get("build-backend", "setuptools.build_meta") != "setuptools.build_meta"
        or "backend-path" in build
    ):
        return {"unreviewed-package-dependency"}
    return set()


def _workflow_dependency_signals(source: str, lock_present: bool) -> set[str]:
    from .build_scan import UnscannableInput, _yaml_document

    try:
        document = _yaml_document(source)
    except UnscannableInput as exc:
        raise GuardInputError from exc
    signals: set[str] = set()
    pending: list[Any] = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
            continue
        if not isinstance(value, dict):
            continue
        if "uses" in value and value["uses"] not in (*_APPROVED_ACTIONS, "./"):
            signals.add("unreviewed-workflow-action")
        if any(key in value for key in ("container", "services")):
            signals.add("unreviewed-workflow-container")
        command = value.get("run")
        if isinstance(command, str):
            for line in command.splitlines():
                match = _INSTALL_COMMAND.search(line)
                if match is None or line.lstrip().startswith("#"):
                    continue
                if lock_present and tuple(shlex.split(line, comments=True)) == _APPROVED_LOCK_INSTALL:
                    continue
                prefix = tuple(shlex.split(line[:match.start()], comments=True))
                arguments = shlex.split(line[match.end():], comments=True)
                if (
                    not match[0].startswith("pip")
                    or "--isolated" in match[0]
                    or prefix not in _APPROVED_PIP_PREFIXES
                    or arguments.count("PyYAML==6.0.3") != 1
                    or any(arg != "PyYAML==6.0.3" and arg not in _APPROVED_PIP_FLAGS for arg in arguments)
                ):
                    signals.add("unreviewed-workflow-install")
        pending.extend(value.values())
    return signals


def _is_workflow(parts: tuple[str, ...]) -> bool:
    return (
        parts in {("action.yml",), ("action.yaml",)}
        or (parts[:2] == (".github", "workflows") and len(parts) == 3 and parts[-1].endswith((".yml", ".yaml")))
        or (parts[:2] == (".github", "actions") and parts[-1] in {"action.yml", "action.yaml"})
    )


def _source_signals(
    parts: tuple[str, ...], raw: bytes, workflow_dependencies: bool, lock_present: bool,
) -> set[str]:
    suffix = PurePosixPath(parts[-1]).suffix.lower()
    if suffix in _SOURCE_IMAGE_SIGNATURES:
        if not raw.startswith(_SOURCE_IMAGE_SIGNATURES[suffix]):
            raise GuardInputError
        if suffix == ".webp" and raw[8:12] != b"WEBP":
            raise GuardInputError
        return _content_signals(raw.decode("latin-1"))
    source = raw.decode("utf-8")
    if "\x00" in source:
        raise GuardInputError
    signals = _content_signals(source)
    if suffix == ".py":
        signals.update(_python_import_signals(source))
    if suffix in _JS_SUFFIXES and any(_has_private_module(module) for module in _JS_IMPORT.findall(source)):
        signals.add("private-import")
    if parts == ("pyproject.toml",):
        signals.update(_project_dependency_signals(source))
    if parts in (_APPROVED_LOCK_PATH, _BUILDER_LOCK_PATH):
        requirements = [line for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if requirements != [_APPROVED_LOCK_LINE if parts == _APPROVED_LOCK_PATH else _BUILDER_LOCK_LINE]:
            signals.add("unreviewed-dependency-manifest")
    if parts[:2] != ("tests", "fixtures") and (
        parts[-1].lower() in _DEPENDENCY_FILES
        or re.fullmatch(r"requirements[^/]*\.(?:txt|in)", parts[-1], re.IGNORECASE)
    ):
        signals.add("unreviewed-dependency-manifest")
    if workflow_dependencies and _is_workflow(parts):
        signals.update(_workflow_dependency_signals(source, lock_present))
    return signals


def scan_source(root: Path, ref: str, scan: GuardScan, *, workflow_dependencies: bool = False) -> None:
    """Read immutable tracked objects without following worktree files or Git links."""
    try:
        scan.commit = _git_object(root, ref + "^{commit}")
        scan.tree = _git_object(root, scan.commit + "^{tree}")
        entries = _git(root, "ls-tree", "-rlz", "--full-tree", scan.tree).split(b"\0")
        if len(entries) - 1 > MAX_TREE_ENTRIES:
            scan.unknown["tree-entry-limit"] += 1
            return
    except (GuardInputError, UnicodeError, ValueError):
        scan.unknown["git-input"] += 1
        return

    lock_path = b"\t" + "/".join(_APPROVED_LOCK_PATH).encode("ascii")
    lock_present = any(entry.endswith(lock_path) for entry in entries)
    path_spellings: dict[str, str] = {}
    total_bytes = 0
    for entry in entries:
        if not entry:
            continue
        scan.source_entries += 1
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
            mode, kind, object_id, size = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
            parts = _path_parts(path)
        except (GuardInputError, UnicodeError, ValueError):
            scan.unknown["unsafe-tracked-path"] += 1
            continue
        # Check every prefix so case-only differences in directory names cannot
        # merge on a case-insensitive clone.
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            canonical = unicodedata.normalize("NFKC", prefix).casefold()
            if path_spellings.setdefault(canonical, prefix) != prefix:
                scan.unknown["colliding-tracked-path"] += 1
                break
        if kind != "blob" or mode not in {"100644", "100755"}:
            scan.unknown["unsafe-tracked-mode"] += 1
            continue
        signals = _path_signals(parts)
        try:
            expected_size = int(size)
            if not _HEX_OBJECT_ID.fullmatch(object_id) or not 0 <= expected_size <= MAX_SOURCE_BYTES:
                raise GuardInputError
            total_bytes += expected_size
            if total_bytes > MAX_TOTAL_SOURCE_BYTES:
                scan.unknown["source-byte-limit"] += 1
                return
            raw = _git(root, "cat-file", "blob", object_id)
            if len(raw) != expected_size:
                raise GuardInputError
            signals.update(_source_signals(parts, raw, workflow_dependencies, lock_present))
        except (GuardInputError, UnicodeError, ValueError, SyntaxError, RecursionError):
            scan.unknown["unsupported-source-content"] += 1
        scan.signals.update(signals)


def _open_report(root: Path, parts: tuple[str, ...]) -> bytes:
    # All ancestors supplied in the selected relative path must be actual
    # directories. Bind each open to the prior descriptor to avoid raceable
    # checks followed by pathname-based access.
    no_follow = os.O_NOFOLLOW
    directory = os.O_RDONLY | os.O_DIRECTORY | no_follow
    descriptor = os.open(root, directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        flags = os.O_RDONLY | no_follow | os.O_NONBLOCK
        report = os.open(parts[-1], flags, dir_fd=descriptor)
        with os.fdopen(report, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_REPORT_BYTES:
                raise GuardInputError
            raw = handle.read(MAX_REPORT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_REPORT_BYTES:
        raise GuardInputError
    return raw


def _report_object(item: list[tuple[str, Any]]) -> dict[str, Any]:
    data = dict(item)
    if len(data) != len(item):
        raise GuardInputError
    return data


def _reject_json_constant(_: str) -> None:
    raise GuardInputError


def _report_content_signals(source: str, suffix: str) -> set[str]:
    signals = _content_signals(source)
    if _PERSONAL_PATH.search(source):
        signals.add("report-local-path")
    if suffix not in {".json", ".jsonl", ".sarif"}:
        return signals
    documents = source.splitlines() if suffix == ".jsonl" else [source]
    for item in documents:
        pending = [json.loads(item, object_pairs_hook=_report_object, parse_constant=_reject_json_constant)]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                for key, field_value in value.items():
                    if _normalize(key) in _PRIVATE_REPORT_FIELDS and field_value not in _REDACTED_FIELD_VALUES:
                        signals.add("report-sensitive-field")
                    pending.extend((key, field_value))
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str):
                signals.update(_content_signals(value))
                if _PERSONAL_PATH.search(value):
                    signals.add("report-local-path")
    return signals


def scan_reports(root: Path, reports: list[str], scan: GuardScan) -> None:
    """Check explicit relative paths from a trusted publication directory."""
    if not reports or len(reports) > MAX_REPORTS or len(set(reports)) != len(reports):
        scan.unknown["report-selection"] += 1
        return
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        scan.unknown["report-platform"] += 1
        return
    for relative in reports:
        scan.report_entries += 1
        try:
            parts = _path_parts(relative)
            suffix = PurePosixPath(parts[-1]).suffix.lower()
            if suffix not in _REPORT_TYPES or any(part.startswith(".") for part in parts):
                raise GuardInputError
            signals = _path_signals(parts)
            text = _open_report(root, parts).decode("utf-8")
            if "\x00" in text:
                raise GuardInputError
            signals.update(_report_content_signals(text, suffix))
            scan.signals.update(signals)
        except (GuardInputError, OSError, UnicodeError, ValueError, RecursionError):
            scan.unknown["unsupported-report-input"] += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref", nargs="?", default="HEAD", help="local commit or ref to inspect")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="local Git checkout")
    parser.add_argument("--workflow-dependencies", action="store_true", help="check action and install policy using PyYAML")
    parser.add_argument("--report-root", type=Path, help="trusted directory prepared for publication")
    parser.add_argument("--report", action="append", default=[], help="relative report file to review")
    args = parser.parse_args(argv)
    scan = GuardScan()
    scan_source(args.repo, args.ref, scan, workflow_dependencies=args.workflow_dependencies)
    if args.report_root is None and args.report:
        scan.unknown["report-selection"] += 1
    elif args.report_root is not None:
        scan_reports(args.report_root, args.report, scan)
    print(json.dumps(scan.result(args.workflow_dependencies), sort_keys=True))
    return 2 if scan.unknown else 1 if scan.signals else 0


if __name__ == "__main__":
    raise SystemExit(main())
