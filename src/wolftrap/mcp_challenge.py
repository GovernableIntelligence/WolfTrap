"""Differential qualification against fixed, independently authored MCP expectations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable

from .agent_scan import _sha
from .canonical import sha256_json
from .mcp_corpus import Case, cases, capture, encoded, server, tool
from .mcp_input import LIMITS, VERSION, Incomplete
from .mcp_rules import inspect


@dataclass(frozen=True)
class Observation:
    code: int
    rules: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    def record(self) -> dict:
        return {"exit_code": self.code, "rule_ids": list(self.rules), "coverage_reasons": list(self.reasons)}


def observe(case: Case) -> Observation:
    result = inspect(case.baseline, case.candidate, case.config, baseline_sha256=case.pin)
    return Observation(result["exit_code"], tuple(sorted({f["rule_id"] for f in result["findings"]})),
                       tuple(sorted({g["reason"] for g in result["coverage_gaps"]})))


def _without(data: Observation, rule: str) -> Observation:
    retained = tuple(r for r in data.rules if r != rule)
    return Observation(2 if data.code == 2 else int(bool(retained)), retained, data.reasons)


# Deliberately defective classifier decisions. Each is scored by precisely the
# same oracle as the candidate, including absence of unexpected rules on negatives.
DEFECTS: dict[str, Callable[[Observation], Observation]] = {
    "flag-everything": lambda _: Observation(1, ("WT-MCP-001",)),
    "flag-nothing": lambda _: Observation(0, ()),
    "accept-incomplete": lambda r: Observation(int(bool(r.rules)), r.rules),
    "ignore-schema-expansion": lambda r: _without(r, "WT-MCP-006"),
    "ignore-cross-server-collisions": lambda r: _without(r, "WT-MCP-004"),
    "trust-authority-claims": lambda r: _without(r, "WT-MCP-005"),
    "ignore-stdio-config": lambda r: _without(r, "WT-MCP-008"),
}


def _io_controls() -> list[dict]:
    """Exercise real descriptor walks and replay, using only disposable authored files."""
    from .mcp_evidence import run_scan

    rows = []
    with TemporaryDirectory(prefix="wolftrap-mcp-") as temporary:
        root = Path(temporary)
        inputs = root / "inputs"
        inputs.mkdir()
        baseline, candidate = inputs / "before.json", inputs / "after.json"
        baseline.write_bytes(encoded(capture(server(tool()))))
        candidate.write_bytes(encoded(capture(server(tool()), sequence=2)))
        (inputs / "link.json").symlink_to(candidate)
        (root / "link-dir").symlink_to(inputs, target_is_directory=True)

        def probe(name: str, expected: str, operation: Callable) -> None:
            expected_code = 0 if expected == "NO_PATTERN_MATCH" else 2
            try:
                report = operation()
                code = report["exit_code"]
                observed = ",".join(sorted({g["reason"] for g in report["coverage_gaps"]})) or report["status"]
            except Incomplete as error:
                code, observed = 2, str(error)
            except OSError:
                code, observed = 2, "unavailable-path"
            rows.append({"id": name, "expected": expected, "observed": observed,
                         "expected_exit": expected_code, "observed_exit": code,
                         "matched": expected == observed and expected_code == code})

        for name, path, reason in (
            ("leaf-symlink", inputs / "link.json", "unavailable-or-unsafe-input"),
            ("parent-symlink", root / "link-dir" / candidate.name, "unavailable-or-unsafe-input"),
            ("parent-traversal", inputs / ".." / "inputs" / candidate.name, "unsafe-local-path"),
        ):
            probe(name, reason, lambda: run_scan(baseline, path, root / name))
        probe("overlapping-output", "evidence-directory-overlaps-input-directory",
              lambda: run_scan(baseline, candidate, inputs / "out"))

        evidence = root / "evidence"
        run_scan(baseline, candidate, evidence)

        def replay() -> dict:
            return run_scan(baseline, candidate, evidence, verify=True)

        probe("intact-evidence", "NO_PATTERN_MATCH", replay)
        for suffix in ("json", "md", "sarif", "manifest.json"):
            member = evidence / ("mcp-scan." + suffix)
            original = member.read_bytes()
            member.write_bytes(original + b"\n")
            probe("altered-" + suffix, "evidence-replay-mismatch", replay)
            member.write_bytes(original)
        baseline.write_bytes(b"\n" + baseline.read_bytes())
        probe("stale-baseline-replay", "evidence-replay-mismatch", replay)
        baseline.write_bytes(baseline.read_bytes()[1:])
        member = evidence / "mcp-scan.sarif"
        member.unlink()
        probe("missing-sarif", "incomplete-evidence-members", replay)
        member.symlink_to(candidate)
        probe("symlinked-sarif", "evidence-replay-mismatch", replay)
    return rows


def evaluate(detector: Callable[[Case], Observation] = observe) -> dict:
    rows = []
    groups: dict[str, dict] = {}
    defect_mismatches = Counter({d: 0 for d in DEFECTS})
    seen = set()
    for case in cases():
        if case.id in seen:
            raise ValueError("duplicate synthetic control identity")
        seen.add(case.id)
        expected = Observation(case.expected_code, tuple(sorted(f"WT-MCP-{r:03}" for r in case.expected_rules)),
                               (case.expected_reason,) if case.expected_reason else ())
        actual = detector(case)
        matched = actual == expected
        group = groups.setdefault(case.group, {"total": 0, "matched": 0})
        group["total"] += 1
        group["matched"] += int(matched)
        for name, defective in DEFECTS.items():
            defect_mismatches[name] += int(defective(actual) != expected)
        rows.append({"id": case.id, "group": case.group, "expected": expected.record(),
                     "observed": actual.record(), "matched": matched, "source_digests": {
                         "baseline": _sha(case.baseline), "candidate": _sha(case.candidate),
                         "config": _sha(case.config) if case.config is not None else None,
                         "baseline_pin": case.pin}})
    io_controls = _io_controls()
    mismatches = sum(not row["matched"] for row in rows + io_controls)
    qualified = len(rows) >= 100 and not mismatches and all(defect_mismatches.values())
    return {
        "schema": "wolftrap.mcp-challenge/v1", "status": "PASSED_BOUNDED" if qualified else "CONTROL_GAP",
        "exit_code": 0 if qualified else 1, "synthetic_only": True, "live_server_tested": False,
        "configuration": {"protocol_version": VERSION, "limits": LIMITS, "corpus": "mcp-controls/v1"},
        "corpus_sha256": sha256_json([{k: v for k, v in row.items() if k not in ("observed", "matched")}
                                      for row in rows]),
        "summary": {"cases": len(rows), "io_controls": len(io_controls), "mismatches": mismatches, "by_group": groups,
                    "defects": len(DEFECTS), "defects_caught": sum(c > 0 for c in defect_mismatches.values())},
        "defective_detector_mismatches": dict(defect_mismatches), "cases": rows, "io_controls": io_controls,
        "limitations": ["Synthetic rule and coverage expectations apply only to the authored inputs.",
                        "Known misses and benign matches document gaps. Production rates are unmeasured.",
                        "Replaying an unsigned bundle establishes consistency with the supplied source revision."],
    }
