"""Descriptor-relative, bounded local reads and exclusive product evidence publication."""

import os
import re
import stat
from pathlib import Path

from .agent_scan import SUFFIXES, _open_directory, _sha

LIMITS = {"entries": 512, "files": 32, "depth": 8, "file_bytes": 32768, "total_bytes": 262144,
          "line_characters": 2048, "findings": 128}
FORMATS = {**dict.fromkeys(SUFFIXES, "agent"), **dict.fromkeys((".md", ".mkd"), "prompt")}
EXCLUDED = {"node_modules", "vendor", "venv", "__pycache__", "keychains", "gnupg"}
PRIVATE_ROOTS = {".git", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".password-store",
                 ".config", "keychains", "gnupg"}
SENSITIVE = re.compile(r"(?:^|[._-])(?:secrets?|credentials?|passwords?|tokens?|id_rsa|id_ed25519)(?:[._-]|$)")
MEMBERS = ("quickscan.json", "quickscan.md", "quickscan.sarif", "quickscan.manifest.json")
DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


class ProductError(ValueError):
    """Only fixed public reason codes may cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise ProductError(code)


def local_path(value):
    text = os.fspath(value)
    path = Path(text)
    require(text and len(os.fsencode(text)) <= 4096 and len(path.parts) <= 64 and ".." not in path.parts
            and not text.startswith("//") and not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", text)
            and "\\" not in text and not any(ord(c) < 32 for c in text), "unsafe-path")
    return path.absolute()


def excluded(name):
    lower = name.casefold()
    return lower.startswith(".") or lower in EXCLUDED or bool(SENSITIVE.search(lower))


def check_root(root):
    require(root != Path("/") and root != Path.home() and not any(
        root.is_relative_to(Path("/") / d) for d in ("dev", "proc", "sys", "etc"))
        and not any(part.casefold() in PRIVATE_ROOTS or SENSITIVE.search(part.casefold())
                    for part in root.parts[1:]), "private-or-system-root")


def mount_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("mnt_id:"):
                return int(line.split()[1])
    raise ProductError("mount-check-unavailable")


def stamp(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read_member(directory, name, limit, mount=None):
    # O_PATH pins an inode without opening a FIFO/device for I/O. A concurrent
    # pathname replacement cannot redirect the actual read through this procfd.
    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "unsafe-file")
        require(before.st_size <= limit, "byte-limit")
        if mount is not None:
            require(mount_id(fd) == mount, "mount-boundary")
        with open(f"/proc/self/fd/{fd}", "rb") as stream:
            data = stream.read(limit + 1)
        require(len(data) == before.st_size and stamp(os.fstat(fd)) == stamp(before)
                and stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp(before), "input-changed")
        return data
    finally:
        os.close(fd)


def selection(values):
    if values is None:
        return None
    require(0 < len(values) <= LIMITS["files"] and len(set(values)) == len(values), "invalid-selection")
    for value in values:
        p = Path(value)
        require(not p.is_absolute() and p.parts and value == p.as_posix() and not any(
            s in (".", "..") or excluded(s) for s in p.parts) and len(p.parts) <= LIMITS["depth"]
            and len(os.fsencode(value)) <= 1024 and "\\" not in value and not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", value)
            and not any(ord(c) < 32 for c in value), "invalid-selection")
    return sorted(values)


def capture(root, selected):
    """A manifest of names, bounded file bytes and temporary race-detection stamps."""
    check_root(root)
    base = _open_directory(root)
    rows, states, counts = {}, {}, {"entries": 0, "excluded": 0, "unsupported": 0, "bytes_read": 0}
    try:
        volume = mount_id(base)
        states[""] = stamp(os.fstat(base))

        def take(parent, name, relative, info):
            require(len(rows) < LIMITS["files"], "file-count-limit")
            detector = FORMATS.get(Path(name).suffix.lower())
            if not detector or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                reason = "unsupported-format" if not detector and stat.S_ISREG(info.st_mode) else "unsafe-file"
                rows[relative] = (detector, None, reason)
                return
            limit = min(LIMITS["file_bytes"], LIMITS["total_bytes"] - counts["bytes_read"])
            if info.st_size > limit:
                rows[relative] = (detector, None, "byte-limit")
                return
            raw = read_member(parent, name, limit, volume)
            counts["bytes_read"] += len(raw)
            states[relative] = stamp(info)
            rows[relative] = (detector, raw, None)

        def walk(parent, parts, depth):
            require(depth <= LIMITS["depth"], "depth-limit")
            names = []
            with os.scandir(parent) as entries:
                for entry in entries:
                    counts["entries"] += 1
                    require(counts["entries"] <= LIMITS["entries"], "entry-limit")
                    names.append(entry.name)
            for name in sorted(names):
                if excluded(name):
                    counts["excluded"] += 1
                    continue
                relative = "/".join((*parts, name))
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, DIR, dir_fd=parent)
                    try:
                        require(stamp(info) == stamp(os.fstat(child)) and mount_id(child) == volume, "unsafe-directory")
                        states[relative] = stamp(info)
                        walk(child, (*parts, name), depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and Path(name).suffix.lower() not in FORMATS:
                    counts["unsupported"] += 1
                else:
                    take(parent, name, relative, info)

        if selected is None:
            walk(base, (), 1)
        else:
            for relative in selected:
                parent = os.dup(base)
                try:
                    parts = Path(relative).parts
                    for part in parts[:-1]:
                        child = os.open(part, DIR, dir_fd=parent)
                        os.close(parent)
                        parent = child
                        require(mount_id(parent) == volume, "mount-boundary")
                    info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    take(parent, parts[-1], relative, info)
                finally:
                    os.close(parent)
        again = _open_directory(root)
        try:
            require(stamp(os.fstat(again)) == states[""], "input-changed")
        finally:
            os.close(again)
        return rows, states, counts
    finally:
        os.close(base)


def disjoint(root, dest, parent_fd=None):
    require(dest.name and not dest.is_relative_to(root) and not root.is_relative_to(dest), "overlapping-evidence")
    # Check physical ancestry too, before the first mkdir. A renamed or bind-aliased
    # root must never turn an output request into a write inside the selected root.
    source = _open_directory(root)
    try:
        source_stat = os.fstat(source)
        parent = _open_directory(dest.parent) if parent_fd is None else os.dup(parent_fd)
        try:
            parent_info = os.fstat(parent)
            require(source_stat.st_dev != parent_info.st_dev or mount_id(source) == mount_id(parent), "mount-boundary")
            require((parent_info.st_uid == os.geteuid() and not parent_info.st_mode & 0o022)
                    or (parent_info.st_mode & stat.S_ISVTX and parent_info.st_uid in (0, os.geteuid(), os.stat("/").st_uid)),
                    "untrusted-evidence-parent")
            for _ in range(65):
                info = os.fstat(parent)
                require(not os.path.samestat(info, source_stat), "overlapping-evidence")
                upper = os.open("..", DIR, dir_fd=parent)
                os.close(parent)
                parent = upper
                if os.path.samestat(info, os.fstat(upper)):
                    break
            else:
                raise ProductError("unsafe-path")
        finally:
            os.close(parent)
    finally:
        os.close(source)


def deliver(dest, files, *, replay, expected_pin=None, source_root=None):
    require(tuple(files) == MEMBERS, "invalid-bundle")
    if expected_pin is not None:
        require(expected_pin == _sha(files[MEMBERS[-1]]), "manifest-pin-mismatch")
    parent = _open_directory(dest.parent)
    try:
        if source_root is not None:
            disjoint(source_root, dest, parent)
        if not replay:
            try:
                os.mkdir(dest.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                raise ProductError("choose-fresh-output") from None
        fd = os.open(dest.name, DIR, dir_fd=parent)
        try:
            start = stamp(os.fstat(fd))
            if replay:
                with os.scandir(fd) as scan:
                    names = set()
                    for e in scan:
                        names.add(e.name)
                        require(len(names) <= len(files), "unexpected-evidence")
                require(names == set(files), "incomplete-evidence")
            for name, raw in files.items():
                if replay:
                    require(read_member(fd, name, len(raw)) == raw, "evidence-mismatch")
                else:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    with os.fdopen(os.open(name, flags, 0o600, dir_fd=fd), "wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
            if replay:
                require(start == stamp(os.fstat(fd)), "evidence-changed")
                # A same-inode in-place edit does not touch the directory timestamp.
                require(all(read_member(fd, n, len(raw)) == raw for n, raw in files.items()), "evidence-changed")
            else:
                os.fsync(fd)
                os.fsync(parent)
            current = _open_directory(dest)
            try:
                require(os.path.samestat(os.fstat(fd), os.fstat(current)), "evidence-changed")
            finally:
                os.close(current)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
