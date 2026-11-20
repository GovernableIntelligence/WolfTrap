"""One explicitly selected local scope. Findings are static review advisories."""

from . import agent_rules, prompt_rules
from .agent_scan import RULES as AGENT_RULES, _json, _sha
from .product_files import LIMITS, MEMBERS, ProductError, capture

TITLES = {**AGENT_RULES, **prompt_rules.RULES}
ACTIONS = {
    "WT-AGENT-001": "Inspect the guardrail error path. Check how the host handles an unavailable decision.",
    "WT-AGENT-002": "Check whether this callback is a test stub or is reachable from a real approval boundary.",
    "WT-AGENT-003": "Trace the value and sink locally. Check whether a browser could receive a real session value.",
    "WT-PROMPT-001": "Review the surrounding instructions and who supplied the document.",
    "WT-PROMPT-002": "Check whether the passage is quoted training material or asks a reader to disclose instructions.",
    "WT-PROMPT-003": "Check the document's origin. Authority must come from the host.",
    "WT-PROMPT-004": "Review the source and destination in context and check the host's data-access policy.",
}
SCOPE = "Visible JS/TS agent source and Markdown documents. Hidden, dependency and credential-store paths are excluded."
LIMITATION = "Static rules can miss indirect calls, quoted instructions, unfamiliar languages and runtime behavior."
NEXT = {"NO_PATTERN_MATCH": "Review the covered files and rule limits before relying on this result.",
        "REVIEW_REQUIRED": "Look up each source ID and line locally. Check context and reachability.",
        "INCONCLUSIVE": "Check the coverage reasons. Select smaller supported files with --file and use a fresh output directory."}


def source_id(relative):
    return _sha(relative.encode("utf-8", errors="surrogateescape"))


def inspect_file(name, detector, raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], ["invalid-utf8"]
    if "\x00" in text or any(len(line) > LIMITS["line_characters"] for line in text.splitlines()):
        return [], ["binary-or-long-line"]
    try:
        if detector == "agent":
            return agent_rules.inspect_text(text)
        return prompt_rules.inspect_prompt_document(name, text), []
    except RecursionError:
        return [], ["parser-depth-limit"]


def analyze(root, selected, build):
    files, findings, reasons, paths = [], [], [], {}
    counts = {"entries": 0, "excluded": 0, "unsupported": 0, "bytes_read": 0}
    stable = False
    try:
        snapshot = capture(root, selected)
        rows, _, counts = snapshot
        for name, (detector, raw, issue) in sorted(rows.items()):
            identifier = source_id(name)
            paths[identifier] = name
            signals, unknowns = ([], [issue]) if issue else inspect_file(name, detector, raw)
            record = {"source_id": identifier, "check": detector, "sha256": _sha(raw) if raw is not None else None,
                      "bytes": len(raw) if raw is not None else None, "incomplete": unknowns}
            files.append(record)
            for signal in signals:
                if len(findings) >= LIMITS["findings"]:
                    reasons.append("finding-limit")
                    break
                findings.append({"source_id": identifier, "line": signal["line"], "rule_id": signal["rule_id"],
                                 "basis": signal["context"], "boundary": signal["boundary"],
                                 "classification": "STATIC REVIEW SIGNAL", "severity": "NOT_RATED",
                                 "confidence": "CONDITIONAL_STATIC", "identity_assurance": "NOT_ASSESSED"})
        if not rows:
            reasons.append("no-supported-input")
        if counts["unsupported"]:
            reasons.append("unsupported-files-in-discovery")
        if capture(root, selected) != snapshot:
            raise ProductError("input-changed")
        stable = True
    except (OSError, ValueError) as exc:
        files, findings, paths = [], [], {}
        reasons = [str(exc) if isinstance(exc, ProductError) else "input-unavailable-or-changed"]
    files.sort(key=lambda f: f["source_id"])
    findings.sort(key=lambda f: (f["source_id"], f["line"], f["rule_id"], f["basis"]))
    incomplete = bool(reasons or any(f["incomplete"] for f in files))
    status = "INCONCLUSIVE" if incomplete else "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH"
    checks = sorted({f["check"] for f in files if f["sha256"] and f["check"] and
                     not {"binary-or-long-line", "invalid-utf8"}.intersection(f["incomplete"])})
    rule_ids = [r for r in TITLES if r.split("-")[1].lower() in checks]
    selection = {"mode": "explicit" if selected is not None else "discovery",
                 "requested_ids": sorted(source_id(n) for n in selected or [])}
    return {"schema": "wolftrap.quickscan/v1", "status": status, "build": build,
            "scope": SCOPE, "selection": selection, "bounds": LIMITS, "coverage": {**counts, "stable_inventory": stable},
            "files": files, "rule_ids_run": sorted(rule_ids), "findings": findings, "incomplete": sorted(set(reasons)),
            "review_rules": {r: {"meaning": TITLES[r], "next_action": ACTIONS[r]} for r in sorted(rule_ids)},
            "finding_class": "STATIC REVIEW SIGNAL", "severity": "NOT_RATED", "confidence": "CONDITIONAL_STATIC",
            "identity_assurance": "NOT_ASSESSED", "conclusive_runtime_observations": 0, "enforced": False,
            "next_action": NEXT[status], "limitations": LIMITATION}, paths


def render(report):
    status = report["status"]
    counts = report["coverage"]
    lines = ["# WolfTrap local review", "", "**" + status + "**", "", report["scope"], "",
             (f"Read {counts['bytes_read']} bytes in the selected pass. Selected {len(report['files'])} files. "
              f"Excluded {counts['excluded']} entries by policy and saw {counts['unsupported']} unsupported regular files.")
             if counts["stable_inventory"] else "A stable inventory was unavailable. Partial observations were discarded.",
             "", "Checks run: " + (", ".join(report["rule_ids_run"]) or "none"), "",
             "## Observations", ""]
    for f in report["findings"]:
        code = f["rule_id"]
        lines += [f"- **{code}** · source `{f['source_id']}`, line {f['line']}. "
                  f"{TITLES[code]}. Evidence: `{f['basis']}`. {ACTIONS[code]}"]
    if not report["findings"]:
        lines.append("No supported pattern was recorded.")
    gaps = [*report["incomplete"], *(f["source_id"] + " · " + ", ".join(f["incomplete"])
             for f in report["files"] if f["incomplete"])]
    lines += ["", "## Unknowns and next action", "", *("- " + g for g in gaps), report["limitations"],
              "", report["next_action"], "", "Use verify-report with --show-paths for local file names. "
              "The JSON inventory contains file digests and the source revision.", ""]
    driver = {"name": "WolfTrap quickscan", "version": report["build"]["version"],
              "rules": [{"id": r, "shortDescription": {"text": TITLES[r]}} for r in report["rule_ids_run"]]}
    results = [{"ruleId": f["rule_id"], "level": "warning", "message": {"text": TITLES[f["rule_id"]]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "source-" + f["source_id"]},
                              "region": {"startLine": f["line"]}}}]} for f in report["findings"]]
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results,
             "invocations": [{"executionSuccessful": status != "INCONCLUSIVE"}], "properties": {"status": status}}]}
    files = {MEMBERS[0]: _json(report), MEMBERS[1]: "\n".join(lines).encode(), MEMBERS[2]: _json(sarif)}
    files[MEMBERS[-1]] = _json({"schema": "wolftrap.quickscan-manifest/v1", "state": "COMPLETE", "status": status,
                                "build": report["build"], "files": {n: {"bytes": len(raw), "sha256": _sha(raw)}
                                                                   for n, raw in files.items()}})
    return files
