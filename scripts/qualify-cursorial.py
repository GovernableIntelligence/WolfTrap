"""Run the exact public Cursorial qualification and cross-check saved witnesses."""

import argparse
import hashlib
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

MEMBERS = ("cursorial.json", "cursorial-chains.json", "cursorial.md", "cursorial.sarif", "cursorial.manifest.json")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    subprocess.run([sys.executable, "-m", *map(str, args)], check=True)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def cross_check(root, head):
    """Read the saved catalog, host and ledger channels without invoking the candidate evaluator."""
    bundle = root / "challenge"
    manifest = json.loads((bundle / MEMBERS[-1]).read_bytes())
    check(manifest["state"] == "COMPLETE" and set(manifest["files"]) == set(MEMBERS[:-1]), "manifest coverage")
    for name, entry in manifest["files"].items():
        raw = (bundle / name).read_bytes()
        check(entry == {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}, "manifest integrity")
    report = json.loads((bundle / MEMBERS[0]).read_bytes())
    records = json.loads((bundle / MEMBERS[1]).read_bytes())["cases"]
    captures = {c["case"]: c["trace"] for c in records}
    rows = report["cases"]
    check(len(rows) == len(captures) == len(records) >= 100 and set(captures) == {r["id"] for r in rows},
          "case inventory")
    check(report["status"] == "PASSED_BOUNDED" and report["source_revision"]["commit_sha"] == head,
          "exact-head qualification")
    attempts = effects = 0
    for row in rows:
        trace = captures[row["id"]]
        check(row["input_sha256"] == digest(trace) and row["matched"], "input or authored expectation")
        if row["classification"] != "SYNTHETICALLY VERIFIED":
            check(not row["witnesses"], "unverified chain reported as observed")
            continue
        sources = trace["sources"]
        facts = {e["id"]: e for e in sources["host"]["events"]}
        ledger = {e["id"]: e for e in sources["ledger"]["events"]}
        captured = {e["id"]: src["alias"] for src in sources.values() for e in src["events"]}
        nodes = row["graph"]["nodes"]
        check(captured == {n["id"]: n["source"] for n in nodes}, "graph provenance mismatch")
        times = {n["id"]: n["at"] for n in nodes}
        check(all(times[e["from"]] < times[e["to"]] for e in row["graph"]["edges"]), "noncausal edge")
        check(len(ledger) == len(row["witnesses"]) > 0, "missing independent windows")
        for witness in row["witnesses"]:
            host = witness["host_witness"]
            window = ledger[witness["ledger_witness"]["event"]]
            oracle = witness["oracle"]
            for phase in ("prepare", "commit"):
                decision = facts[host[phase + "_event"]]
                check(decision["phase"] == phase and decision["binding"] == witness["binding"]
                      and decision["decision"] == host[phase] == oracle[phase], "host/reference disagreement")
            check(window["commit"] == host["commit_event"] and window["records"] ==
                  witness["ledger_witness"]["records"] == oracle["records"], "ledger/reference disagreement")
            check(window["after_count"] - window["before_count"] == len(window["records"]), "effect delta")
            attempts += 1
            effects += len(window["records"])
    check(all(m["caught"] and m["reproduction"]["minimized_events"] < m["reproduction"]["original_events"]
              for m in report["mutants"]) and report["summary"]["gate_mutants_caught"] == 9,
          "defect reproduction")
    check(report["summary"]["unstable_reproduction_rejected"] and report["summary"]["always_alert_gaps"] > 0
          and report["summary"]["always_silent_gaps"] > 0, "negative control qualification")
    return {"summary": report["summary"], "cross_checked_attempts": attempts, "cross_checked_effects": effects}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--parent-netns")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = repository_root()
    os.chdir(root)
    source = capture_source_revision(root)
    check(not source.dirty and source.commit_sha == args.expected_head, "clean exact head required")
    if args.parent_netns:
        check(os.readlink("/proc/self/ns/net") != args.parent_netns and {n for _, n in socket.if_nameindex()} == {"lo"},
              "network namespace isolation failed")
    out = args.output_dir.absolute()
    check(out == out.resolve() and not out.is_relative_to(root), "fresh evidence outside checkout required")
    out.mkdir(mode=0o700)
    run("wolftrap.public_guard", args.expected_head)
    run("wolftrap.test_runner", "--pattern", "test_cursorial*.py", "--output", out / "unit-tests.json")
    unit = json.loads((out / "unit-tests.json").read_bytes())
    check(unit["successful"] and unit["tests_run"] > 0 and not unit["skipped"] and not unit["expected_failures"]
          and unit["source_revision"] == source.to_dict(), "isolated regression gate")
    groups = {"challenge": (), "selected": ("--chain", "examples/cursorial/authorized.json")}
    with tempfile.TemporaryDirectory() as temp:
        for group, options in groups.items():
            for dest in (out / group, Path(temp) / group):
                run("wolftrap", "challenge-cursorial", "--expected-head", args.expected_head, *options, "--output-dir", dest)
                run("wolftrap", "verify-cursorial", "--expected-head", args.expected_head, *options, "--evidence-dir", dest)
            for name in MEMBERS:
                check((out / group / name).read_bytes() == (Path(temp) / group / name).read_bytes(), "unstable replay")
    measured = cross_check(out, args.expected_head)
    check(capture_source_revision(root) == source, "qualification source changed")
    write_json_report({"schema": "wolftrap.cursorial-qualification/v1", "status": "PASSED_BOUNDED",
                       "source_revision": source.to_dict(), "python": platform.python_version(),
                       "loopback_only_namespace_verified": bool(args.parent_netns), "unit_tests": unit["tests_run"],
                       "byte_identical_artifacts": len(groups) * len(MEMBERS), **measured}, out / "qualification.json")
    names = ["qualification.json", "unit-tests.json", *(f"{group}/{name}" for group in groups for name in MEMBERS)]
    run("wolftrap.public_guard", args.expected_head, "--report-root", out,
        *(part for name in names for part in ("--report", name)))


if __name__ == "__main__":
    main()
