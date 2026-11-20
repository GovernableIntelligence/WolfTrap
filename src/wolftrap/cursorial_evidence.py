"""Fixed-name publication and byte-for-byte replay at the trusted scanner revision."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from .agent_scan import _json, _open_directory, _read_file, _sha
from .canonical import sha256_json
from .cursorial import LIMITATIONS, UNKNOWN, inspect_capture, qualify
from .cursorial_trace import LIMITS, Gap, decode, need
from .revision import repository_root

MEMBERS = ("cursorial.json", "cursorial-chains.json", "cursorial.md", "cursorial.sarif",
           "cursorial.manifest.json")


def _stamp(s: os.stat_result) -> tuple:
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink


def _member(fd: int, name: str, limit: int) -> bytes:
    start = os.stat(name, dir_fd=fd, follow_symlinks=False)
    need(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size <= limit,
         "unsafe-or-oversized-member")
    data = _read_file(fd, name, limit)
    need(_stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == _stamp(start), "unstable-file")
    return data


def _path(value: str | Path) -> Path:
    path = Path(value)
    need(bool(path.name) and ".." not in path.parts and not any(p.casefold() == ".git" for p in path.parts)
         and len(str(value)) <= 4096 and len(path.absolute().parts) <= 64 and "\\" not in str(value)
         and not str(value).startswith("//") and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", str(value))
         and not any(ord(c) < 32 for c in str(value)), "unsafe-local-path")
    return path.absolute()


def _input(path: Path) -> bytes:
    fd = _open_directory(path.parent)
    try:
        return _member(fd, path.name, LIMITS["bytes"])
    finally:
        os.close(fd)


def source_identity(expected: str | None) -> dict:
    """Read only immutable Git objects and bounded tracked files in the engine package."""
    root = repository_root()
    need((root / ".git").exists(), "trusted-source-checkout-required")
    env = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ALLOW_PROTOCOL": "",
           "GIT_OPTIONAL_LOCKS": "0"}

    def git(*args: str) -> bytes:
        try:
            return subprocess.run(["git", *args], cwd=root, env=env, check=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=10).stdout
        except (subprocess.SubprocessError, OSError):
            raise Gap("source-identity-unavailable") from None

    commit = git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    tree = git("rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
    need(expected is None or commit == expected, "source-revision-pin-mismatch")
    rows = git("ls-tree", "-rz", commit, "--", "src/wolftrap").split(b"\0")[:-1]
    need(0 < len(rows) <= 256, "source-package-bound")
    total = 0
    checked = set()
    for row in rows:
        header, name = row.split(b"\t", 1)
        mode, kind, oid = header.split()
        path = Path(name.decode("utf-8"))
        need(mode in (b"100644", b"100755") and kind == b"blob" and path.is_relative_to("src/wolftrap")
             and ".." not in path.parts, "unsafe-source-package")
        fd = _open_directory((root / path).parent)
        try:
            raw = _read_file(fd, path.name, 1024 * 1024)
        finally:
            os.close(fd)
        total += len(raw)
        need(total <= 8 * 1024 * 1024, "source-package-bound")
        digest = hashlib.new("sha1" if len(oid) == 40 else "sha256", f"blob {len(raw)}\0".encode() + raw)
        need(digest.hexdigest() == oid.decode(), "tracked-engine-changed")
        checked.add(path.as_posix())
    required = {"src/wolftrap/cursorial" + suffix for suffix in
                (".py", "_lab.py", "_oracle.py", "_trace.py", "_corpus.py", "_evidence.py")}
    required.update("src/wolftrap/schemas/cursorial-" + s + "-v1.schema.json" for s in ("chain", "graph"))
    need(required <= checked, "source-package-incomplete")
    return {"commit_sha": commit, "tree_sha": tree, "tracked_package_verified": True}


def _render(report: dict, archive: dict) -> dict[str, bytes]:
    lines = ["# WolfTrap Cursorial Intelligence Engine", "", "**" + report["status"] + "**", "",
             "Mode " + report["mode"], "", "Commit " + report["source_revision"]["commit_sha"],
             "", "Tree " + report["source_revision"]["tree_sha"], ""]
    results = []

    def signal(rule: str, message: str, level: str, **properties) -> None:
        results.append({"ruleId": rule, "level": level, "message": {"text": message}, "properties": properties})

    def case_signals(row: dict, case_id: str) -> None:
        for a in row["advisories"]:
            signal("WT-CIE-SCENT", "Untrusted fictional metadata or agent claim", "note", case=case_id, **a)
        if row["classification"] == UNKNOWN:
            signal("WT-CIE-GAP", row["reason"], "note", case=case_id, classification=UNKNOWN)

    if report["mode"] == "qualification":
        summary = report["summary"]
        lines += [f"{summary['cases']} authored cases, {summary['mismatches']} mismatches.", "",
                  "| Case | Expected attempts or gap | Observed class | Matched |", "| --- | --- | --- | --- |"]
        for row in report["cases"]:
            expected = row["expected_gap"] or ", ".join(row["expected_attempts"]) or "metadata only"
            lines.append(f"| {row['id']} | {expected} | {row['classification']} | {row['matched']} |")
            case_signals(row, row["id"])
            if not row["matched"]:
                signal("WT-CIE-CONTROL", "Authored expectation mismatch", "error", case=row["id"])
        lines += ["", "## Defective controls", "", "| Model | Case | Events before → after | Reproduced |",
                  "| --- | --- | --- | --- |"]
        for m in report["mutants"]:
            r = m["reproduction"]
            lines.append(f"| {m['mutant']} | {m['case']} | {r['original_events']} → "
                         f"{r.get('minimized_events', 'unknown')} | {m['caught']} |")
            if not m["caught"]:
                signal("WT-CIE-CONTROL", "Defective control escaped qualification", "error", mutant=m["mutant"])
        if report["status"] == "CONTROL_GAP" and not any(r["level"] == "error" for r in results):
            signal("WT-CIE-CONTROL", "A qualification gate failed", "error")
    else:
        row = report["capture"]
        case_signals(row, "selected")
        lines += [row["reason"], "", "| Binding | Host prepare / commit | Expected / observed effect delta |",
                  "| ---: | --- | --- |"]
        for w in row["witnesses"]:
            h = w["host_witness"]
            lines.append(f"| {w['binding']} | {h['prepare']} / {h['commit']} | "
                         f"{len(w['oracle']['records'])} / {len(w['ledger_witness']['records'])} |")
        for v in report["pursuit"]:
            lines += ["", f"- {v['variation']} · {v['classification']} · {v['reason']}"]
    lines += ["", "## Limits", ""] + ["- " + item for item in LIMITATIONS] + [""]
    rules = {"WT-CIE-SCENT": "Static review signal", "WT-CIE-GAP": "Incomplete fictional evidence",
             "WT-CIE-CONTROL": "Synthetic qualification mismatch"}
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "WolfTrap Cursorial",
             "rules": [{"id": k, "shortDescription": {"text": v}} for k, v in rules.items()]}},
             "invocations": [{"executionSuccessful": report["exit_code"] != 2}],
             "results": results, "properties": {"mode": report["mode"], "status": report["status"]}}]}
    files = {MEMBERS[0]: _json(report), MEMBERS[1]: _json(archive), MEMBERS[2]: "\n".join(lines).encode(),
             MEMBERS[3]: _json(sarif)}
    files[MEMBERS[4]] = _json({"schema": "wolftrap.cursorial-manifest/v1", "state": "COMPLETE",
                               "source_revision": report["source_revision"], "mode": report["mode"],
                               "files": {name: {"bytes": len(raw), "sha256": _sha(raw)} for name, raw in files.items()}})
    return files


def _deliver(files: dict[str, bytes], target: Path, verify: bool) -> None:
    fd = _open_directory(target, create=not verify)
    try:
        start = _stamp(os.fstat(fd))
        with os.scandir(fd) as scan:
            if not verify:
                need(next(scan, None) is None, "output-directory-not-empty")
            else:
                names = set()
                for item in scan:
                    names.add(item.name)
                    need(len(names) <= len(files), "unexpected-evidence-member")
                need(names == files.keys(), "incomplete-evidence-directory")
        stamps = {}
        for name, raw in files.items():
            if verify:
                stamps[name] = _stamp(os.stat(name, dir_fd=fd, follow_symlinks=False))
                need(_member(fd, name, len(raw)) == raw, "evidence-replay-mismatch")
            else:
                member = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(member, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
        if verify:
            for name, stamp in stamps.items():
                need(_stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stamp, "unstable-evidence")
            need(_stamp(os.fstat(fd)) == start, "unstable-evidence")
            selected = _open_directory(target)
            try:
                need(_stamp(os.fstat(selected)) == start, "unstable-evidence-directory")
            finally:
                os.close(selected)
        else:
            os.fsync(fd)
    finally:
        os.close(fd)


def run(directory: str | Path, *, chain: str | Path | None = None, expected_head: str | None = None,
        verify: bool = False) -> dict:
    out = _path(directory)
    path = _path(chain) if chain is not None else None
    if path is not None:
        need(not out.is_relative_to(path.parent) and not path.parent.is_relative_to(out),
             "evidence-overlaps-input-directory")
    revision = source_identity(expected_head)
    if path is None:
        report, archive = qualify()
    else:
        raw = _input(path)
        archive = {"schema": "wolftrap.cursorial-selected-input/v1", "sha256": _sha(raw), "bytes": len(raw)}
        try:
            doc = decode(raw)
            archive["canonical_sha256"] = sha256_json(doc)
            report = inspect_capture(doc)
        except Gap as gap:
            report = {"schema": "wolftrap.cursorial-evidence/v1", "mode": "selected-fictional-capture",
                      "status": UNKNOWN, "exit_code": 2, "capture": {"classification": UNKNOWN,
                      "reason": str(gap), "graph": None, "advisories": [], "witnesses": [], "discrepancies": []},
                      "pursuit": [], "pursuit_gaps": 0, "fresh_capture_sha256": [], "limits": LIMITS,
                      "limitations": LIMITATIONS}
        report["source_sha256"] = _sha(raw)
    report.update(source_revision=revision, synthetic_only=True, live_agents_tested=False,
                  production_effects=0, authorization_changes=0)
    files = _render(report, archive)
    need(source_identity(revision["commit_sha"]) == revision, "engine-changed-during-analysis")
    if path is not None:
        need(_input(path) == raw, "input-changed-during-analysis")
    _deliver(files, out, verify)
    if verify and path is not None:
        need(_input(path) == raw, "input-changed-during-replay")
    return report


def command(args) -> int:
    verify = args.command == "verify-cursorial"
    try:
        report = run(args.evidence_dir if verify else args.output_dir, chain=args.chain,
                     expected_head=args.expected_head, verify=verify)
        print(("VERIFIED_EVIDENCE " if verify else "") + report["status"])
        return report["exit_code"]
    except Gap as gap:
        print("INCONCLUSIVE " + str(gap))
    except (ValueError, OSError):
        print("INCONCLUSIVE unsafe or unavailable local evidence")
    return 2
