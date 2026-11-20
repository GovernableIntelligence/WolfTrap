"""Readiness of a pinned wheel installation. No network, Git or target lookup."""

import json
import os
import platform
import re
import sys
from pathlib import Path

from .agent_scan import _json, _open_directory, _sha
from .product_files import ProductError, mount_id, read_member, require

BUILD = "product-build-v1.json"
VERSION = "0.5.4.dev1"
PACKAGE = Path(__file__).absolute().parent


def compatible():
    return (sys.platform == "linux" and platform.python_implementation() == "CPython"
            and sys.version_info[:2] == (3, 12) and platform.machine() in ("x86_64", "aarch64")
            and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_PATH")
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and os.scandir in os.supports_fd)


def _unique(pairs):
    data = dict(pairs)
    require(len(data) == len(pairs), "invalid-build-record")
    return data


def installation(package=PACKAGE):
    require(compatible(), "unsupported-platform")
    data_fd = _open_directory(package / "data")
    try:
        mount_id(data_fd)
        doc = json.loads(read_member(data_fd, BUILD, 65536), object_pairs_hook=_unique)
    finally:
        os.close(data_fd)
    require(type(doc) is dict and set(doc) == {"schema", "version", "commit", "tree", "members"}
            and doc["schema"] == "wolftrap.product-build/v1"
            and all(isinstance(doc[k], str) and re.fullmatch(r"[a-f0-9]{40}", doc[k]) for k in ("commit", "tree"))
            and doc["version"] == VERSION,
            "invalid-build-record")
    members = doc["members"]
    require(type(members) is dict and 1 <= len(members) <= 256
            and {"product_install.py", "product_scan.py", "product_files.py", "product_cli.py", "agent_rules.py",
                 "prompt_rules.py", "agent_scan.py", "cli.py"} <= members.keys(), "invalid-build-record")
    total = 0
    for name, expected in members.items():
        require(re.fullmatch(r"(?:[a-zA-Z0-9_-]+/){0,4}[a-zA-Z0-9_.-]+\.(?:py|json|md|js)", name)
                and type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "invalid-build-record")
        path = package / name
        directory = _open_directory(path.parent)
        try:
            raw = read_member(directory, path.name, min(1024 * 1024, 8 * 1024 * 1024 - total))
        finally:
            os.close(directory)
        require(_sha(raw) == expected, "installed-member-changed")
        total += len(raw)
    return {**{k: doc[k] for k in ("version", "commit", "tree")}, "build_record_sha256": _sha(_json(doc)),
            "verified_package_members": len(members)}


def readiness():
    try:
        build = installation()
    except ProductError as exc:
        return {"ready": False, "reason": str(exc), "build": None}
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return {"ready": False, "reason": "missing-or-unreadable-build-record", "build": None}
    return {"ready": True, "reason": "verified-installation", "build": build}
