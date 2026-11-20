"""Qualify MCP Bloodhound from an exact, clean public checkout."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from wolftrap.report import write_json_report
from wolftrap.revision import capture_source_revision, repository_root

PIN = "8c237f492ac371509368e0ad29861e0f414b5a3ea17a443bc7f06543eca28b9a"
BUNDLES = {"review": "mcp-scan", "negative": "mcp-scan", "challenge": "mcp-challenge"}
SUFFIXES = ("json", "md", "sarif", "manifest.json")


def run(*args: str | Path, expected: int = 0) -> None:
    code = subprocess.run([sys.executable, "-m", *map(str, args)], check=False).returncode
    if code != expected:
        raise ValueError(f"{args[0]} {args[1]} returned {code}, expected {expected}")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def bundles(out: Path) -> None:
    base = Path("examples/mcp/baseline.json")
    for name, candidate, code in (("review", base.with_name("candidate.json"), 1), ("negative", base, 0)):
        opts = ("--baseline", base, "--baseline-sha256", PIN, "--candidate", candidate)
        run("wolftrap", "scan-mcp", *opts, "--output-dir", out / name, expected=code)
        run("wolftrap", "verify-mcp", *opts, "--evidence-dir", out / name, expected=code)
    run("wolftrap", "challenge-mcp", "--output-dir", out / "challenge")
    run("wolftrap", "verify-mcp-challenge", "--evidence-dir", out / "challenge")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--parent-netns", help="namespace ID read in the parent before isolation")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    repo = repository_root()
    os.chdir(repo)
    revision = capture_source_revision(repo)
    check(not revision.dirty and revision.commit_sha == args.expected_head, "clean exact checkout required")
    if args.parent_netns is not None:
        check(args.parent_netns != os.readlink("/proc/self/ns/net")
              and {name for _, name in socket.if_nameindex()} == {"lo"}, "network namespace isolation failed")
    out = args.output_dir.absolute()
    check(out == out.resolve() and not out.is_relative_to(repo), "fresh output outside checkout required")
    out.mkdir(mode=0o700)
    run("wolftrap.public_guard", args.expected_head)
    run("wolftrap.test_runner", "--pattern", "test_mcp*.py", "--output", out / "unit-tests.json")
    unit = json.loads((out / "unit-tests.json").read_bytes())
    check(unit["successful"] and unit["tests_run"] > 0 and not unit["skipped"]
          and not unit["expected_failures"] and unit["source_revision"] == revision.to_dict(),
          "MCP unit tests did not qualify")
    bundles(out)
    files = [f"{group}/{stem}.{suffix}" for group, stem in BUNDLES.items() for suffix in SUFFIXES]
    with tempfile.TemporaryDirectory() as temp:
        duplicate = Path(temp)
        bundles(duplicate)
        for name in files:
            check((out / name).read_bytes() == (duplicate / name).read_bytes(), "nonreproducible artifact")
    review = json.loads((out / "review/mcp-scan.json").read_bytes())
    rules = sorted({signal["rule_id"] for signal in review["findings"]})
    check(rules == ["WT-MCP-002", "WT-MCP-003", "WT-MCP-005", "WT-MCP-006", "WT-MCP-007"]
          and review["confirmed_findings"] == 0 and not review["coverage_gaps"], "fixture review changed")
    negative = json.loads((out / "negative/mcp-scan.json").read_bytes())
    check(not negative["findings"] and not negative["coverage_gaps"], "negative fixture changed")
    challenge = json.loads((out / "challenge/mcp-challenge.json").read_bytes())
    summary = challenge["summary"]
    check(challenge["status"] == "PASSED_BOUNDED" and summary["cases"] >= 100
          and summary["defects_caught"] == summary["defects"] >= 2 and summary["io_controls"] >= 10
          and not summary["mismatches"], "synthetic controls did not qualify")
    check(capture_source_revision(repo) == revision, "source changed during qualification")
    write_json_report({
        "schema": "wolftrap.mcp-qualification/v1", "status": "PASSED_BOUNDED",
        "source_revision": revision.to_dict(), "python": platform.python_version(),
        "system": platform.system(), "loopback_only_namespace_verified": args.parent_netns is not None,
        "isolated_unit_tests": unit["tests_run"], "review_fixture_rule_ids": rules,
        "negative_fixture_signals": len(negative["findings"]), "challenge": summary,
        "reproduced_and_replayed_bundles": list(BUNDLES), "byte_identical_artifacts": len(files),
    }, out / "qualification.json")
    selected = ["qualification.json", "unit-tests.json", *files]
    run("wolftrap.public_guard", args.expected_head, "--report-root", out,
        *(arg for member in selected for arg in ("--report", member)))


if __name__ == "__main__":
    main()
