"""Source-bound replay and manifest-last publication for MCP Bloodhound."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import unicodedata
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _read_file, _sha
from .mcp_input import HEX, LIMITS, VERSION, Incomplete, require
from .mcp_rules import LIMITATIONS, RULES, inspect
from .revision import repository_root

SCAN = "mcp-scan"
CHALLENGE = "mcp-challenge"


def _read(path: Path, bound: int) -> bytes:
    fd = _open_directory(path.parent)
    try:
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= bound, "unsafe-or-oversized-file")
        return _read_file(fd, path.name, bound)
    finally:
        os.close(fd)


def scanner_revision() -> dict:
    """Use Git only on the trusted scanner checkout. Never run Git on an input path.

    Compare tracked package bytes to immutable blob IDs, avoiding Git filters, hooks,
    working-tree discovery and any traversal of unrelated untracked target material.
    """
    root = repository_root()
    require((root / ".git").exists(), "scanner-checkout-unavailable")
    env = {"PATH": os.defpath, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_ALLOW_PROTOCOL": "", "LC_ALL": "C"}

    def git(*args: str) -> bytes:
        return subprocess.run(["git", *args], cwd=root, env=env, check=True, timeout=10,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout

    try:
        commit = git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
        tree = git("rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
        require(all(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", v) for v in (commit, tree)),
                "unavailable-source-identity")
        entries = git("ls-tree", "-rz", commit, "--", "src/wolftrap").split(b"\0")[:-1]
        require(0 < len(entries) <= 256, "scanner-package-bound")
        total = 0
        checked = set()
        for entry in entries:
            header, name = entry.split(b"\t", 1)
            mode, kind, oid = header.split()
            path = Path(name.decode("utf-8"))
            require(mode in (b"100644", b"100755") and kind == b"blob"
                    and path.is_relative_to("src/wolftrap") and ".." not in path.parts,
                    "unsupported-scanner-package")
            content = _read(root / path, 1024 * 1024)
            total += len(content)
            require(total <= 8 * 1024 * 1024, "scanner-package-bound")
            algorithm = "sha1" if len(oid) == 40 else "sha256"
            blob = hashlib.new(algorithm, f"blob {len(content)}\0".encode() + content)
            require(blob.hexdigest() == oid.decode(), "scanner-package-differs-from-revision")
            checked.add(path.name)
        require({"mcp_input.py", "mcp_rules.py", "mcp_evidence.py", "mcp_challenge.py",
                 "mcp_corpus.py", "cli.py"} <= checked, "scanner-package-differs-from-revision")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, Incomplete):
            raise
        raise Incomplete("unavailable-source-identity") from None
    return {"commit_sha": commit, "tree_sha": tree, "tracked_package_verified": True}


def _path(value: str | Path) -> Path:
    path = Path(value)
    require(len(str(value)) <= 4096 and not str(value).startswith("//")
            and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", str(value))
            and path.name not in ("", ".", "..") and ".." not in path.parts
            and not any(unicodedata.normalize("NFKC", p).casefold() == ".git" for p in path.parts)
            and not any(c == "\\" or unicodedata.category(c).startswith("C") for c in str(value)),
            "unsafe-local-path")
    absolute = path.absolute()
    require(len(absolute.parts) <= LIMITS["path_components"], "local-path-depth-limit")
    return absolute


def _members(fd: int, maximum: int) -> set[str]:
    names = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            names.add(entry.name)
            require(len(names) <= maximum, "unexpected-evidence-members")
    return names


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _bundle(stem: str, report: dict) -> dict[str, bytes]:
    scan = stem == SCAN
    lines = ["# MCP Bloodhound " + ("inspection" if scan else "synthetic qualification"), "",
             "**" + report["status"] + "**", "",
             "Scanner commit " + report["source_revision"]["commit_sha"],
             "  ", "Scanner tree " + report["source_revision"]["tree_sha"], ""]
    results = []
    if scan:
        for role, source in report["sources"].items():
            lines.append(f"- {role} SHA-256 " + (source["sha256"] or "unavailable"))
        lines.extend(["", f"Review signals {len(report['findings'])}. "
                          f"Coverage gaps {len(report['coverage_gaps'])}.", ""])
        for signal in report["findings"]:
            lines.extend([f"### {signal['rule_id']} · {signal['title']}", "",
                          f"{signal['basis']} ({signal['field']}, {signal['scope']}).",
                          "", signal["limitation"] + " " + signal["possible_benign_explanation"], ""])
            for key, value in sorted(signal["observed"].items()):
                display = ", ".join(value) if isinstance(value, list) else str(value)
                lines.append(f"- {key.replace('_', ' ')} `{display if value is not None else 'absent'}`")
            if signal["observed"]:
                lines.append("")
            results.append({"ruleId": signal["rule_id"], "level": "warning",
                            "message": {"text": signal["basis"]}, "properties": signal})
        for gap in report["coverage_gaps"]:
            lines.append(f"- Incomplete {gap['role']} inspection ({gap['scope']}, {gap['reason']})")
        rules = {k: v[0] for k, v in RULES.items()}
    else:
        lines += [f"{report['summary']['cases']} authored cases. "
                  f"{report['summary']['mismatches']} mismatches.", "",
                  "| Control group | Cases | Matched |", "| --- | ---: | ---: |"]
        for group, counts in report["summary"]["by_group"].items():
            lines.append(f"| {group} | {counts['total']} | {counts['matched']} |")
        lines.extend(["", "| Defective detector | Failed controls |", "| --- | ---: |"])
        for defect, count in report["defective_detector_mismatches"].items():
            lines.append(f"| {defect} | {count} |")
        lines.extend(["", "| Filesystem or evidence control | Match |", "| --- | --- |"])
        for case in report["io_controls"]:
            lines.append(f"| {case['id']} | {'yes' if case['matched'] else 'no'} |")
        rules = {"WT-MCP-QUAL": "Synthetic qualification mismatch"}
        for case in report["cases"] + report["io_controls"]:
            if not case["matched"]:
                results.append({"ruleId": "WT-MCP-QUAL", "level": "error",
                                "message": {"text": "Authored control mismatch at " + case["id"]}})
        for defect, count in report["defective_detector_mismatches"].items():
            if count == 0:
                results.append({"ruleId": "WT-MCP-QUAL", "level": "error",
                                "message": {"text": "Defective detector escaped qualification at " + defect}})
    lines += ["", "## Limitations", ""] + ["- " + item for item in report["limitations"]] + [""]
    invocation: dict[str, Any] = {"executionSuccessful": report["exit_code"] != 2}
    if scan and report["coverage_gaps"]:
        invocation["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": gap["reason"]}, "properties": gap}
            for gap in report["coverage_gaps"]]
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "WolfTrap MCP Bloodhound",
                       "rules": [{"id": k, "shortDescription": {"text": v}} for k, v in rules.items()]}},
                       "invocations": [invocation], "results": results,
                       "properties": {"status": report["status"], "source_revision": report["source_revision"]}}]}
    files = {stem + ".json": _json(report), stem + ".md": "\n".join(lines).encode(),
             stem + ".sarif": _json(sarif)}
    files[stem + ".manifest.json"] = _json({
        "schema": "wolftrap." + stem + "-manifest/v1", "state": "COMPLETE",
        "source_revision": report["source_revision"],
        "files": {name: {"bytes": len(raw), "sha256": _sha(raw)} for name, raw in files.items()},
    })
    return files


def _deliver(stem: str, report: dict, directory: Path, verify: bool) -> None:
    files = _bundle(stem, report)
    fd = _open_directory(directory, create=not verify)
    try:
        if verify:
            directory_stamp = _stamp(os.fstat(fd))
            require(_members(fd, len(files)) == files.keys(), "incomplete-evidence-members")
            # Never parse or trust caller-supplied manifest/report instructions or counts.
            # Expected bytes (including every manifest field) come from a fresh replay.
            stamps = {}
            for name, expected in files.items():
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(expected)
                        and _read_file(fd, name, len(expected)) == expected, "evidence-replay-mismatch")
                stamps[name] = _stamp(info)
            for name, stamp in stamps.items():
                require(_stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stamp,
                        "evidence-changed-during-replay")
            require(_stamp(os.fstat(fd)) == directory_stamp, "evidence-changed-during-replay")
        else:
            with os.scandir(fd) as entries:
                require(next(entries, None) is None, "output-directory-not-empty")
            # Exclusive creation reserves the first fixed name for one writer. A
            # partial publication has no valid COMPLETE manifest and cannot verify.
            for name, raw in files.items():
                member = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                with os.fdopen(member, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(fd)
    finally:
        os.close(fd)


def run_scan(baseline: str | Path, candidate: str | Path, directory: str | Path, *,
             config: str | Path | None = None, baseline_sha256: str | None = None,
             verify: bool = False) -> dict:
    paths = {"baseline": _path(baseline), "candidate": _path(candidate)}
    if config is not None:
        paths["config"] = _path(config)
    dest = _path(directory)
    for path in paths.values():
        require(not dest.is_relative_to(path.parent) and not path.parent.is_relative_to(dest),
                "evidence-directory-overlaps-input-directory")
    require(baseline_sha256 is None or bool(HEX.fullmatch(baseline_sha256)), "invalid-baseline-pin")
    revision = scanner_revision()

    def inputs() -> dict:
        result = {}
        for role, path in paths.items():
            try:
                bound = LIMITS["config_bytes" if role == "config" else "snapshot_bytes"]
                result[role] = _read(path, bound)
            except (ValueError, OSError):
                result[role] = None
        return result

    raw = inputs()
    report = inspect(**raw, baseline_sha256=baseline_sha256, config_selected=config is not None)
    report.update({"schema": "wolftrap.mcp-scan/v1", "source_revision": revision,
                   "configuration": {"protocol_version": VERSION, "limits": LIMITS,
                                     "unicode_data_version": unicodedata.unidata_version,
                                     "baseline_pin_sha256": baseline_sha256,
                                     "config_profile": "local-stdio/v1" if config is not None else None},
                   "trust_boundary": "untrusted metadata to static review advisory",
                   "target_code_executed": False, "network_contacted": False, "authorization_decisions": 0,
                   "confirmed_findings": 0, "limitations": LIMITATIONS})
    require(inputs() == raw, "inputs-changed-during-inspection")
    _deliver(SCAN, report, dest, verify)
    if verify:
        require(inputs() == raw, "inputs-changed-during-replay")
    return report


def command(args: Any) -> int:
    """Keep OS errors, target paths and rejected payloads out of CLI output."""
    try:
        verify = args.command.startswith("verify")
        dest = args.evidence_dir if verify else args.output_dir
        if args.command in ("scan-mcp", "verify-mcp"):
            report = run_scan(args.baseline, args.candidate, dest, config=args.config,
                              baseline_sha256=args.baseline_sha256, verify=verify)
        else:
            from .mcp_challenge import evaluate
            report = evaluate()
            report["source_revision"] = scanner_revision()
            _deliver(CHALLENGE, report, _path(dest), verify)
        print(("VERIFIED_EVIDENCE " if verify else "") + report["status"])
        return report["exit_code"]
    except Incomplete as error:
        print("INCONCLUSIVE " + str(error))
    except OSError:
        print("INCONCLUSIVE unsafe or unavailable local evidence path")
    return 2
