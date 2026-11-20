"""SURROUND and CONFIRM: compare independent witnesses and reproduce synthetic failures."""

from __future__ import annotations

from collections import Counter
from typing import Callable

from .canonical import sha256_json
from .cursorial_corpus import VARIANTS, Case, cases, corrupt, vary
from .cursorial_lab import execute, schedule
from .cursorial_oracle import reference
from .cursorial_trace import LIMITS, Gap, scent, track

VERIFIED = "SYNTHETICALLY VERIFIED"
STATIC = "STATIC REVIEW SIGNAL"
UNKNOWN = "INCONCLUSIVE"
LIMITATIONS = [
    "Witness channels are independently implemented inside one fictional laboratory. Source labels cannot authenticate a file's publisher.",
    "The model has one host chain, bounded logical time, serialized ledger windows and process-local recovery.",
    "A quoted approval marker can raise a benign advisory. An actor indistinguishable from an authorized session can evade detection.",
    "Live swarms, genuine runtime authorization, malware identification, human attribution and incident prevention are untested.",
]


def assess(doc: dict) -> dict:
    try:
        tracked = track(doc)
    except Gap as gap:
        try:
            markers = scent(doc)
        except Gap:
            markers = []
        return {"classification": UNKNOWN, "reason": str(gap), "graph": None, "advisories": markers,
                "witnesses": [], "discrepancies": []}
    result = {"classification": VERIFIED, "reason": "complete-witness-agreement", "graph": tracked.graph,
              "advisories": tracked.advisories, "witnesses": [], "discrepancies": []}
    if doc["mode"] == "metadata":
        result.update(classification=STATIC if tracked.advisories else UNKNOWN,
                      reason="metadata-only" if tracked.advisories else "no-behavior-witness")
        return result
    gates, windows = {}, {}
    for e in tracked.events:
        if e["kind"] == "gate_decision":
            gates[e["binding"], e["phase"]] = e
        elif e["kind"] == "effect_observed":
            windows[e["commit"]] = e
    for row in reference(tracked.events):
        binding = row["binding"]
        prepare, commit = gates[binding, "prepare"], gates[binding, "commit"]
        window = windows[commit["id"]]
        expected = {k: row[k] for k in ("prepare", "commit", "records")}
        observed = {"prepare": prepare["decision"], "commit": commit["decision"], "records": window["records"]}
        witness = {"binding": binding, "operation_digest": row["digest"], "oracle": expected,
                   "host_witness": {"prepare_event": prepare["id"], "prepare": observed["prepare"],
                                    "commit_event": commit["id"], "commit": observed["commit"]},
                   "ledger_witness": {"event": window["id"], "before": window["before_count"],
                                      "after": window["after_count"], "before_hash": window["before_hash"],
                                      "after_hash": window["after_hash"], "records": window["records"]}}
        result["witnesses"].append(witness)
        differences = {k: {"expected": expected[k], "observed": observed[k]}
                       for k in expected if observed[k] != expected[k]}
        if differences:
            mismatch = {"binding": binding, "operation_digest": row["digest"], "differences": differences}
            result["discrepancies"].append({**mismatch, "fingerprint": sha256_json(mismatch)})
    if result["discrepancies"]:
        result.update(classification=UNKNOWN, reason="witness-disagreement-awaiting-reproduction")
    return result


def _trial(plan: list[dict], factory: Callable[[], str]) -> dict:
    try:
        result = assess(execute(plan, factory()))
    except (Gap, KeyError):
        # Deleting a required producer can leave a dangling reference in the proposed reduction.
        return {"fingerprint": None, "witness": None, "differences": []}
    if not result["discrepancies"]:
        return {"fingerprint": None, "witness": None, "differences": []}
    first = result["discrepancies"][0]
    witness = next(w for w in result["witnesses"] if w["binding"] == first["binding"])
    return {"fingerprint": first["fingerprint"], "witness": witness, "differences": sorted(first["differences"])}


def confirm(plan: list[dict], factory: Callable[[], str], target: str | None = None) -> dict:
    """Preserve the same semantic disagreement while removing executable schedule events."""
    initial = _trial(plan, factory)
    fingerprint = target or initial["fingerprint"]
    report = {"classification": UNKNOWN, "original_schedule_sha256": sha256_json(plan),
              "original_events": len(plan), "fingerprint": fingerprint, "original": initial,
              "initial_replays": [], "minimized_replays": [], "minimization_evaluations": 0}
    if not fingerprint or initial["fingerprint"] != fingerprint:
        return report
    initial_replays = [_trial(plan, factory)["fingerprint"] for _ in range(LIMITS["fresh_replays"])]
    report["initial_replays"] = initial_replays
    if any(f != fingerprint for f in initial_replays):
        return report
    reduced = list(plan)
    i = 0
    while i < len(reduced) and report["minimization_evaluations"] < LIMITS["minimization_evaluations"]:
        trial = reduced[:i] + reduced[i + 1:]
        report["minimization_evaluations"] += 1
        if _trial(trial, factory)["fingerprint"] == fingerprint:
            reduced, i = trial, 0
        else:
            i += 1
    replays = [_trial(reduced, factory) for _ in range(LIMITS["fresh_replays"])]
    report.update(minimized_schedule=reduced, minimized_schedule_sha256=sha256_json(reduced),
                  minimized_events=len(reduced), single_deletion_search_complete=i == len(reduced),
                  minimized_replays=replays)
    if all(r["fingerprint"] == fingerprint and r["witness"] == replays[0]["witness"] for r in replays):
        report["classification"] = VERIFIED
    return report


def _labels(result: dict) -> tuple[str, ...]:
    return tuple("/".join((w["host_witness"]["prepare"], w["host_witness"]["commit"],
                           str(len(w["ledger_witness"]["records"])))) for w in result["witnesses"])


def _matches(case: Case, result: dict, alert: bool) -> bool:
    if case.gap:
        return result["classification"] == UNKNOWN and result["reason"] == case.gap and not result["discrepancies"]
    classification = STATIC if case.mode == "metadata" else VERIFIED
    return (result["classification"] == classification and _labels(result) == case.expected
            and not result["discrepancies"] and alert == case.advisory)


# The expected discrepant witness components are authored separately from each mutant.
MUTANTS = {
    "always-allow": ("unregistered-1", {"prepare", "commit", "records"}),
    "always-deny": ("baseline-2", {"prepare", "commit", "records"}),
    "claim-is-grant": ("authority-forgery-1", {"prepare", "commit", "records"}),
    "omit-identity": ("foreign-tenant-2", {"prepare", "commit", "records"}),
    "skip-final": ("revoke-after-prepare-2", {"commit", "records"}),
    "forget-slot": ("replay-1", {"prepare", "commit", "records"}),
    "fake-success": ("baseline-1", {"records"}),
    "wrong-tool-effect": ("baseline-1", {"records"}),
    "effect-on-deny": ("unregistered-2", {"records"}),
}


def qualify(control: str = "correct", alert_detector: Callable[[dict], bool] | None = None) -> tuple[dict, dict]:
    corpus = cases()
    by_id = {c.id: c for c in corpus}
    if len(by_id) != len(corpus) or len(corpus) < 100:
        raise ValueError("incomplete synthetic corpus")
    rows, inputs, regressions = [], [], []
    group_counts, classes = Counter(), Counter()
    false_alert_gaps = silent_gaps = 0
    for case in corpus:
        trace = execute(case.plan, control, mode=case.mode)
        if case.corruption:
            trace = corrupt(trace, case.corruption)
        result = assess(trace)
        alert = bool(result["advisories"]) if alert_detector is None else alert_detector(result)
        matched = _matches(case, result, alert)
        false_alert_gaps += int(not _matches(case, result, True))
        silent_gaps += int(not _matches(case, result, False))
        if result["discrepancies"] and len(regressions) < 4:
            regressions.append({"case": case.id, "reproduction": confirm(
                case.plan, lambda: control, result["discrepancies"][0]["fingerprint"])})
        group_counts[case.group] += 1
        classes[result["classification"]] += 1
        rows.append({"id": case.id, "group": case.group, "input_sha256": sha256_json(trace),
                     "schedule_sha256": sha256_json(case.plan), "parent_schedule_sha256": case.parent or None,
                     "expected_attempts": list(case.expected), "expected_gap": case.gap or None,
                     "expected_advisory": case.advisory, "matched": matched, **result})
        inputs.append({"case": case.id, "trace": trace})
    defects = []
    for mutant, (case_id, difference_keys) in MUTANTS.items():
        reproduction = confirm(by_id[case_id].plan, lambda: mutant)
        caught = (reproduction["classification"] == VERIFIED
                  and set(reproduction["original"]["differences"]) == difference_keys)
        defects.append({"mutant": mutant, "case": case_id, "caught": caught, "reproduction": reproduction})
    oscillating = iter(("fake-success", "correct", "fake-success"))
    unstable = confirm(by_id["baseline-1"].plan, lambda: next(oscillating, "correct"))
    unstable_rejected = (unstable["classification"] == UNKNOWN and None in unstable["initial_replays"])
    mismatches = sum(not r["matched"] for r in rows)
    qualified = (not mismatches and all(d["caught"] for d in defects) and unstable_rejected
                 and false_alert_gaps > 0 and silent_gaps > 0)
    report = {"schema": "wolftrap.cursorial-evidence/v1", "mode": "qualification",
              "status": "PASSED_BOUNDED" if qualified else "CONTROL_GAP", "exit_code": 0 if qualified else 1,
              "summary": {"cases": len(rows), "mismatches": mismatches, "by_group": dict(group_counts),
                          "by_classification": dict(classes), "gate_mutants_caught": sum(d["caught"] for d in defects),
                          "gate_mutants": len(defects), "always_alert_gaps": false_alert_gaps,
                          "always_silent_gaps": silent_gaps, "unstable_reproduction_rejected": unstable_rejected},
              "cases": rows, "mutants": defects, "unstable_control": unstable, "candidate_failures": regressions,
              "limits": LIMITS, "limitations": LIMITATIONS}
    return report, {"schema": "wolftrap.cursorial-fixtures/v1", "cases": inputs}


def inspect_capture(doc: dict) -> dict:
    """Replay a selected fictional capture; never use a submitted decision to drive a write."""
    result = assess(doc)
    variants = []
    fresh = []
    if doc["mode"] == "behavior" and result["graph"] is not None:
        plan = schedule(track(doc))
        for _ in range(LIMITS["fresh_replays"]):
            fresh.append(sha256_json(execute(plan)))
        if any(digest != sha256_json(doc) for digest in fresh):
            result.update(classification=UNKNOWN, reason="selected-capture-not-reproduced")
        for variant in VARIANTS:
            try:
                changed = vary(plan, variant)
                derived = execute(changed)
                verdict = assess(derived)
                variants.append({"variation": variant, "parent_schedule_sha256": sha256_json(plan),
                                 "input_sha256": sha256_json(derived), "classification": verdict["classification"],
                                 "attempts": list(_labels(verdict)), "reason": verdict["reason"]})
            except Gap as gap:
                variants.append({"variation": variant, "classification": UNKNOWN, "reason": str(gap)})
    pursuit_gaps = sum(v["classification"] == UNKNOWN for v in variants)
    status = UNKNOWN if pursuit_gaps else result["classification"]
    return {"schema": "wolftrap.cursorial-evidence/v1", "mode": "selected-fictional-capture",
            "status": status, "exit_code": {VERIFIED: 0, STATIC: 1, UNKNOWN: 2}[status],
            "capture": result, "fresh_capture_sha256": fresh, "pursuit": variants, "pursuit_gaps": pursuit_gaps,
            "limits": LIMITS, "limitations": LIMITATIONS}
