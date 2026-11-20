"""Bounded command-line interface for WolfTrap synthetic research."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from .build_scan import MANIFEST_NAME as BUILD_SCAN_MANIFEST, scan_build
from .challenge import CHALLENGE_MANIFEST, run_challenge, verify_challenge_evidence
from .execution import execute_case
from .model import ExperimentCase
from .report import (
    REPORT_MANIFEST_NAME,
    validate_report_pair,
    write_json_report,
    write_report_pair,
)
from .revision import capture_source_revision
from .runner import RunConfiguration, run_research
from .scenario import ScenarioValidationError, load_corpus
from .stage2 import STAGE2_MANIFEST, STAGE2_REPORT, Stage2Configuration, run_stage2
from .system import SYSTEMS


def _strict_json(path: Path) -> Any:
    def reject(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)


def _unit_summary(
    path: str | None, current_revision: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    if path is None:
        return None
    value = _strict_json(Path(path))
    if not isinstance(value, dict):
        raise ValueError("unit-test summary must be a JSON object")
    required = {"tests_run", "skipped", "failures", "errors", "successful"}
    if not required.issubset(value):
        raise ValueError("unit-test summary is missing required counts")
    for key in ("tests_run", "skipped", "failures", "errors"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError(f"unit-test summary {key} must be non-negative")
    if value["tests_run"] < 1:
        raise ValueError("unit-test summary must contain at least one executed test")
    if value["failures"] or value["errors"] or value["successful"] is not True:
        raise ValueError("unit tests did not pass; research execution stopped safely")
    if (
        value.get("source_revision") != dict(current_revision)
        or value.get("source_revision_end") != dict(current_revision)
        or value.get("source_stable") is not True
    ):
        raise ValueError(
            "unit-test summary source revision does not match this research run"
        )
    return value


def _run(arguments: argparse.Namespace) -> int:
    revision = capture_source_revision()
    configuration = RunConfiguration(
        seed=arguments.seed,
        max_mutations=arguments.max_mutations,
        max_interactions=arguments.max_interactions,
        max_commands_per_case=arguments.max_commands_per_case,
        max_minimization_evaluations=arguments.max_minimization_evaluations,
        reproduction_attempts=arguments.reproduction_attempts,
        system_id=arguments.sut,
        scenario_ids=tuple(arguments.scenario or ()),
    )
    outcome = run_research(
        configuration,
        scenario_directory=arguments.scenario_directory,
        source_revision=revision,
        unit_test_summary=_unit_summary(
            arguments.unit_test_summary, revision.to_dict()
        ),
        reproduction_report_path=str(
            Path(arguments.output_dir) / "wolftrap-report.json"
        ),
    )
    json_path, markdown_path = write_report_pair(outcome.report, arguments.output_dir)
    summary = outcome.report["summary"]
    print(
        f"{outcome.report['qualification']['status']}: "
        f"{summary['cases_executed']}/{summary['cases_generated']} cases executed; "
        f"{summary['findings']} finding(s); {summary['internal_errors']} internal error(s)."
    )
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    print(f"Completion manifest: {Path(arguments.output_dir) / REPORT_MANIFEST_NAME}")
    return outcome.exit_code


def _list_scenarios(arguments: argparse.Namespace) -> int:
    scenarios = load_corpus(arguments.scenario_directory)
    if arguments.json:
        print(
            json.dumps(
                [
                    {
                        "scenario_id": item.scenario_id,
                        "version": item.scenario_version,
                        "category": item.category,
                        "title": item.title,
                        "definition_digest": item.definition_digest,
                    }
                    for item in scenarios
                ],
                sort_keys=True,
                indent=2,
            )
        )
    else:
        for item in scenarios:
            print(f"{item.scenario_id}\t{item.scenario_version}\t{item.title}")
    return 0


def _sweep(arguments: argparse.Namespace) -> int:
    """Run bounded, complete-pair synthetic campaigns without a model/API."""

    revision = capture_source_revision()
    outcome = run_stage2(
        Stage2Configuration(
            first_seed=arguments.seed,
            seed_count=arguments.seed_count,
            mutation_budget=arguments.mutation_budget,
            system_id=arguments.sut,
        ),
        output_dir=arguments.output_dir,
        unit_test_summary=_unit_summary(arguments.unit_test_summary, revision.to_dict()),
    )
    summary = outcome.report["summary"]
    pairs = outcome.report["pair_coverage"]
    print(
        f"{outcome.report['qualification']['status']}: "
        f"{summary['campaigns_executed']} seed(s), "
        f"{summary['cases_executed']} cases, "
        f"{pairs['unique_pairs_reached']}/{pairs['candidate_pairs']} scenario pairs, "
        f"{summary['findings']} synthetic finding(s)."
    )
    print(f"Summary: {Path(arguments.output_dir) / STAGE2_REPORT}")
    print(f"Completion manifest: {Path(arguments.output_dir) / STAGE2_MANIFEST}")
    return outcome.exit_code


def _scan_build(arguments: argparse.Namespace) -> int:
    """Produce bounded local static triage; never execute inspected code."""
    outcome = scan_build(arguments.root, arguments.output_dir)
    summary = outcome.report["summary"]
    print(
        f"{outcome.report['qualification']['status']}: "
        f"{summary['files_inspected']} files, "
        f"{summary['findings']} review-required signal(s), "
        f"{summary['errors']} unknown input(s)."
    )
    print(f"Evidence: {Path(arguments.output_dir)}")
    print(f"Manifest: {Path(arguments.output_dir) / BUILD_SCAN_MANIFEST}")
    return outcome.exit_code


def _scan_agent(arguments: argparse.Namespace) -> int:
    from .agent_scan import scan_agent

    outcome = scan_agent(arguments.root, arguments.output_dir, files=arguments.file)
    print(f"{outcome.report['qualification']['status']}: "
          f"{outcome.report['summary']['files_inspected']} files; "
          f"{outcome.report['summary']['findings']} conditional review signal(s).")
    return outcome.exit_code


def _scan_effects(arguments: argparse.Namespace) -> int:
    from .effect_scan import scan_effects

    outcome = scan_effects(arguments.root, arguments.output_dir, files=arguments.file)
    summary = outcome.report["summary"]
    print(f"{outcome.report['qualification']['status']}: "
          f"{summary['files_inspected']} files; {summary['findings']} conditional boundary signal(s); "
          f"{summary['errors']} unknown input(s).")
    return outcome.exit_code


def _verify_effects(arguments: argparse.Namespace) -> int:
    from .effect_scan import verify_effect_evidence

    report = verify_effect_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['qualification']['status']}; "
          f"{report['summary']['findings']} conditional boundary signal(s).")
    return 0


def _scan_go_authority(arguments: argparse.Namespace) -> int:
    from .go_scan import scan_go_authority

    outcome = scan_go_authority(arguments.root, arguments.output_dir, files=arguments.file)
    summary = outcome.report["summary"]
    print(f"{outcome.report['qualification']['status']}: "
          f"{summary['files_inspected']} Go files; "
          f"{summary['findings']} conditional authority signal(s); "
          f"{summary['errors']} unknown input(s).")
    return outcome.exit_code


def _verify_go_authority(arguments: argparse.Namespace) -> int:
    from .go_scan import verify_go_evidence

    report = verify_go_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['qualification']['status']}; "
          f"{report['summary']['findings']} conditional Go authority signal(s).")
    return 0


def _scan_prompts(arguments: argparse.Namespace) -> int:
    from .prompt_scan import scan_prompts

    outcome = scan_prompts(arguments.root, arguments.output_dir, files=arguments.file)
    summary = outcome.report["summary"]
    print(f"{outcome.report['qualification']['status']}: "
          f"{summary['files_inspected']} documents; "
          f"{summary['findings']} conditional instruction signal(s); "
          f"{summary['errors']} unknown input(s).")
    return outcome.exit_code


def _verify_prompts(arguments: argparse.Namespace) -> int:
    from .prompt_scan import verify_prompt_evidence

    report = verify_prompt_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['qualification']['status']}; "
          f"{report['summary']['findings']} conditional instruction signal(s).")
    return 0


def _challenge_cloud_c2(arguments: argparse.Namespace) -> int:
    from .cloud_c2 import run_cloud_c2_challenge

    report, code = run_cloud_c2_challenge(arguments.output_dir)
    print(f"{report['qualification']['status']}: "
          f"{report['summary']['cases']} synthetic cloud cases; "
          f"{report['summary']['mismatches']} differential gap(s).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_cloud_c2(arguments: argparse.Namespace) -> int:
    from .cloud_c2 import verify_cloud_c2_evidence

    report = verify_cloud_c2_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['cases']} synthetic cloud cases; "
          f"{report['summary']['mismatches']} gap(s).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _challenge_authority(arguments: argparse.Namespace) -> int:
    from .authority_funnel import run_authority_challenge

    report, code = run_authority_challenge(arguments.output_dir)
    summary = report["summary"]
    print(f"{report['qualification']['status']}: "
          f"{summary['cases']} synthetic authority controls; "
          f"{summary['proposals']} inert agent proposals; "
          f"{summary['mismatches']} mismatch(es).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_authority(arguments: argparse.Namespace) -> int:
    from .authority_funnel import verify_authority_evidence

    report = verify_authority_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['cases']} authority controls; "
          f"{report['summary']['mismatches']} mismatch(es).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _challenge_sandbox_authority(arguments: argparse.Namespace) -> int:
    from .sandbox_funnel import run_challenge

    report, code = run_challenge(arguments.output_dir)
    print(f"{report['qualification']['status']}: "
          f"{report['summary']['stages']} synthetic isolation/authority stages; "
          f"{report['summary']['intents']} inert intents; "
          f"{report['summary']['mismatches']} mismatch(es).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_sandbox_authority(arguments: argparse.Namespace) -> int:
    from .sandbox_funnel import verify_evidence

    report = verify_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['stages']} synthetic stages; "
          f"{report['summary']['mismatches']} mismatch(es).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _challenge_artex_chain(arguments: argparse.Namespace) -> int:
    from .artex_chain import run_challenge

    report, code = run_challenge(arguments.output_dir)
    summary = report["summary"]
    print(f"{report['qualification']['status']}: {summary['cases']} inert multi-step chains; "
          f"{summary['attempts']} simulated attempts; "
          f"{summary['mismatches']} differential gap(s).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _cursorial(arguments: argparse.Namespace) -> int:
    from .cursorial_evidence import command

    return command(arguments)


def _verify_artex_chain(arguments: argparse.Namespace) -> int:
    from .artex_chain import verify_evidence

    report = verify_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['cases']} inert chains; "
          f"{report['summary']['mismatches']} differential gap(s).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _challenge_cloud_camouflage(arguments: argparse.Namespace) -> int:
    from .cloud_camouflage import run_camouflage_challenge

    report, code = run_camouflage_challenge(arguments.output_dir)
    stats = report["summary"]
    print(f"{report['qualification']['status']}: {stats['cases']} authored cloud cases; "
          f"{stats['mismatches']} expectation mismatch(es); "
          f"{stats['benign_lookalikes_flagged']} benign lookalikes flagged; "
          f"{stats['evasion_variants_unflagged']} blind-spot cases unflagged.")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_cloud_camouflage(arguments: argparse.Namespace) -> int:
    from .cloud_camouflage import verify_camouflage_evidence

    report = verify_camouflage_evidence(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['cases']} camouflage cases; "
          f"{report['summary']['mismatches']} expectation mismatch(es).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _challenge_cloud_authority(arguments: argparse.Namespace) -> int:
    from .cloud_authority import run_cloud_authority

    report, code = run_cloud_authority(arguments.output_dir)
    stats = report["summary"]
    print(f"{report['qualification']['status']}: "
          f"{stats['cloud_traces']} synthetic cloud traces; "
          f"{stats['authority_checks']} independent synthetic authority checks; "
          f"{stats['mismatches']} mismatch(es).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_cloud_authority(arguments: argparse.Namespace) -> int:
    from .cloud_authority import verify_cloud_authority

    report = verify_cloud_authority(arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['summary']['authority_checks']} "
          f"synthetic authority checks; {report['summary']['mismatches']} mismatch(es).")
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _scan_cloud_trace(arguments: argparse.Namespace) -> int:
    from .cloud_trace import scan_cloud_trace

    report, code = scan_cloud_trace(arguments.root, arguments.file, arguments.output_dir)
    print(f"{report['qualification']['status']}: "
          f"{report['input']['event_count']} normalized events; "
          f"{report['summary']['findings']} conditional correlation(s); "
          f"{report['summary']['errors']} unknown input(s).")
    print(f"Evidence: {Path(arguments.output_dir)}")
    return code


def _verify_cloud_trace(arguments: argparse.Namespace) -> int:
    from .cloud_trace import verify_cloud_trace

    report = verify_cloud_trace(arguments.root, arguments.file, arguments.evidence_dir)
    print(f"VERIFIED_EVIDENCE: {report['qualification']['status']}; "
          f"{report['summary']['findings']} conditional correlation(s).")
    return 0


def _challenge_agent(arguments: argparse.Namespace) -> int:
    from .agent_challenge import run_agent_challenge

    report, code = run_agent_challenge(seed=arguments.seed, output_dir=arguments.output_dir)
    print(json.dumps(report['summary'], sort_keys=True))
    return code


def _verify_agent_challenge(arguments: argparse.Namespace) -> int:
    from .agent_challenge import verify_agent_challenge_evidence

    report = verify_agent_challenge_evidence(arguments.evidence_dir)
    print(json.dumps(report['summary'], sort_keys=True))
    return 0 if report['qualification']['status'] == 'PASSED_BOUNDED' else 1


def _challenge_gt_vsa(arguments: argparse.Namespace) -> int:
    from .gt_vsa_challenge import write_evidence

    manifest = write_evidence(arguments.output_dir, seed=arguments.seed, vehicles=arguments.vehicles)
    status = manifest["status"]
    print(f"{status} synthetic vehicle qualification. Evidence at {arguments.output_dir}")
    return {"PASS": 0, "FAIL": 1}.get(status, 2)


def _verify_gt_vsa(arguments: argparse.Namespace) -> int:
    from .gt_vsa_challenge import verify_evidence

    manifest = verify_evidence(arguments.evidence_dir)
    status = manifest["status"]
    print(f"Reproduced synthetic vehicle evidence with qualification status {status}.")
    return {"PASS": 0, "FAIL": 1}.get(status, 2)


def _replay_agent_challenge(arguments: argparse.Namespace) -> int:
    from .agent_challenge import replay_agent_challenge

    report, code = replay_agent_challenge(arguments.evidence_dir, arguments.output_dir)
    print(json.dumps(report['summary'], sort_keys=True))
    return code


def _challenge_build(arguments: argparse.Namespace) -> int:
    """Stress the static detector with synthetic, independently labelled cases."""
    report, code = run_challenge(
        seed=arguments.seed, count=arguments.cases, output_dir=arguments.output_dir
    )
    print(
        f"{report['qualification']['status']}: "
        f"{report['summary']['cases']} synthetic cases, "
        f"{report['summary']['mismatches']} differential gap(s)."
    )
    print(f"Evidence: {Path(arguments.output_dir)}")
    print(f"Manifest: {Path(arguments.output_dir) / CHALLENGE_MANIFEST}")
    return code


def _verify_challenge(arguments: argparse.Namespace) -> int:
    report = verify_challenge_evidence(arguments.evidence_dir)
    print(
        f"VERIFIED_EVIDENCE: {report['summary']['cases']} saved synthetic cases; "
        f"{report['summary']['mismatches']} differential gap(s)."
    )
    return 0 if report["qualification"]["status"] == "PASSED_BOUNDED" else 1


def _reproduce(arguments: argparse.Namespace) -> int:
    if re.fullmatch(r"WOLFTRAP-F-[A-F0-9]{20}", arguments.finding_id) is None:
        raise ValueError("finding id has an invalid format")
    report = validate_report_pair(Path(arguments.report))
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("input is not a WolfTrap research report")
    matches = [
        item
        for item in report["findings"]
        if isinstance(item, dict) and item.get("finding_id") == arguments.finding_id
    ]
    if len(matches) != 1:
        raise ValueError("finding id must identify exactly one report finding")
    finding = matches[0]
    configuration = finding.get("test_configuration")
    if not isinstance(configuration, dict):
        raise ValueError("finding has no saved test configuration")
    saved_case = configuration.get("minimized_case")
    if not isinstance(saved_case, dict):
        raise ValueError("finding has no saved minimized case")
    case = ExperimentCase.from_dict(saved_case)
    expected_digest = configuration.get("minimized_case_digest")
    if case.digest != expected_digest:
        raise ValueError("saved minimized case digest does not match its evidence")
    system_id = str(configuration.get("system_id"))
    if system_id not in SYSTEMS:
        raise ValueError(f"saved finding names an unknown system: {system_id}")
    execution = execute_case(case, SYSTEMS[system_id])
    expected_fingerprint = finding["independent_effect_state_evidence"][
        "oracle_fingerprint"
    ]
    reproduced = (
        not execution.assessment.passed
        and execution.assessment.fingerprint == expected_fingerprint
    )
    current_revision = capture_source_revision()
    original_revision = finding.get("source_revision", {})
    source_matches = (
        isinstance(original_revision, dict)
        and original_revision.get("commit_sha") == current_revision.commit_sha
        and original_revision.get("tree_sha") == current_revision.tree_sha
        and original_revision.get("dirty") == current_revision.dirty
        and original_revision.get("diff_digest") == current_revision.diff_digest
    )
    result = {
        "reproduction_schema_version": "1.0",
        "finding_id": arguments.finding_id,
        "synthetic_only": True,
        "real_world_vulnerability_claim": False,
        "system_id": system_id,
        "saved_case_digest": expected_digest,
        "actual_case_digest": case.digest,
        "expected_oracle_fingerprint": expected_fingerprint,
        "actual_oracle_fingerprint": execution.assessment.fingerprint,
        "violation_reproduced": reproduced,
        "source_revision_matches": source_matches,
        "original_source_revision": original_revision,
        "current_source_revision": current_revision.to_dict(),
        "execution": execution.to_dict(include_trace=True),
    }
    output = Path(arguments.output_dir) / (
        f"wolftrap-reproduction-{arguments.finding_id}.json"
    )
    write_json_report(result, output)
    print(
        f"{'REPRODUCED' if reproduced else 'NOT_REPRODUCED'}: "
        f"{arguments.finding_id}; source match={source_matches}; evidence={output}"
    )
    if not source_matches:
        return 2
    return 1 if reproduced else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wolftrap",
        description=(
            "WolfTrap: no external targets. Bounded synthetic research and offline "
            "local build, agent, protected-effect and prompt-document inspection."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run a bounded synthetic campaign")
    run.add_argument("--seed", type=int, default=20261113)
    run.add_argument("--max-mutations", type=int, default=32)
    run.add_argument("--max-interactions", type=int, default=8)
    run.add_argument("--max-commands-per-case", type=int, default=128)
    run.add_argument("--max-minimization-evaluations", type=int, default=64)
    run.add_argument("--reproduction-attempts", type=int, default=2)
    run.add_argument("--sut", choices=sorted(SYSTEMS), default="correct-v1")
    run.add_argument("--scenario", action="append")
    run.add_argument("--scenario-directory")
    run.add_argument("--unit-test-summary")
    run.add_argument("--output-dir", default="reports")
    run.set_defaults(handler=_run)

    sweep = subparsers.add_parser(
        "sweep", help="run autonomous full-pair synthetic research across bounded seeds"
    )
    sweep.add_argument("--seed", type=int, default=20261113)
    sweep.add_argument("--seed-count", type=int, default=3)
    sweep.add_argument("--mutation-budget", type=int, default=128)
    sweep.add_argument("--sut", choices=sorted(SYSTEMS), default="correct-v1")
    sweep.add_argument("--unit-test-summary")
    sweep.add_argument("--output-dir", default="reports/stage2")
    sweep.set_defaults(handler=_sweep)

    scanner = subparsers.add_parser(
        "scan-build",
        help="inspect local GitHub Actions and container build definitions without execution",
    )
    scanner.add_argument("--root", required=True, help="local source directory to inspect read-only")
    scanner.add_argument("--output-dir", required=True, help="fresh evidence directory outside source")
    scanner.set_defaults(handler=_scan_build)

    agent = subparsers.add_parser("scan-agent", help="offline conditional JS/TS agent trust-boundary review")
    agent.add_argument("--root", required=True)
    agent.add_argument("--output-dir", required=True)
    agent.add_argument("--file", action="append", help="explicit root-relative source file (repeatable)")
    agent.set_defaults(handler=_scan_agent)

    effects = subparsers.add_parser(
        "scan-effects", help="Stage 5.2 offline agent execution, credential, skill and network triage")
    effects.add_argument("--root", required=True)
    effects.add_argument("--output-dir", required=True)
    effects.add_argument("--file", action="append", help="explicit root-relative source path (repeatable)")
    effects.set_defaults(handler=_scan_effects)

    effect_verify = subparsers.add_parser("verify-effects", help="verify saved Stage 5.2 evidence")
    effect_verify.add_argument("--evidence-dir", required=True)
    effect_verify.set_defaults(handler=_verify_effects)

    go_scanner = subparsers.add_parser(
        "scan-go-authority", help="offline conditional Go tool-permission and egress review")
    go_scanner.add_argument("--root", required=True)
    go_scanner.add_argument("--output-dir", required=True)
    go_scanner.add_argument("--file", action="append",
                            help="explicit root-relative .go source file (repeatable)")
    go_scanner.set_defaults(handler=_scan_go_authority)

    go_verify = subparsers.add_parser(
        "verify-go-authority", help="verify saved Go authority scan evidence")
    go_verify.add_argument("--evidence-dir", required=True)
    go_verify.set_defaults(handler=_verify_go_authority)

    prompts = subparsers.add_parser(
        "scan-prompts", help="Stage 5.3 offline untrusted prompt-document triage")
    prompts.add_argument("--root", required=True)
    prompts.add_argument("--output-dir", required=True)
    prompts.add_argument("--file", action="append", help="explicit root-relative document (repeatable)")
    prompts.set_defaults(handler=_scan_prompts)

    prompt_verify = subparsers.add_parser("verify-prompts", help="verify saved Stage 5.3 evidence")
    prompt_verify.add_argument("--evidence-dir", required=True)
    prompt_verify.set_defaults(handler=_verify_prompts)

    cloud_c2 = subparsers.add_parser(
        "challenge-cloud-c2", help="run GitDoor-inspired synthetic cloud-C2 controls offline")
    cloud_c2.add_argument("--output-dir", required=True,
                          help="fresh directory for synthetic challenge evidence")
    cloud_c2.set_defaults(handler=_challenge_cloud_c2)

    cloud_c2_verify = subparsers.add_parser(
        "verify-cloud-c2", help="verify saved cloud-C2 challenge evidence")
    cloud_c2_verify.add_argument("--evidence-dir", required=True)
    cloud_c2_verify.set_defaults(handler=_verify_cloud_c2)

    authority = subparsers.add_parser(
        "challenge-authority-funnel",
        help="run inert ARTEX-informed tool-claim and agent-swarm authority controls",
    )
    authority.add_argument("--output-dir", required=True, help="fresh evidence directory")
    authority.set_defaults(handler=_challenge_authority)

    authority_verify = subparsers.add_parser(
        "verify-authority-funnel",
        help="verify synthetic authority-funnel challenge evidence",
    )
    authority_verify.add_argument("--evidence-dir", required=True)
    authority_verify.set_defaults(handler=_verify_authority)

    sandbox = subparsers.add_parser(
        "challenge-sandbox-authority",
        help="run a three-stage 1,000-intent synthetic sandbox + authority composition test",
    )
    sandbox.add_argument("--output-dir", required=True, help="fresh evidence directory")
    sandbox.set_defaults(handler=_challenge_sandbox_authority)

    sandbox_verify = subparsers.add_parser(
        "verify-sandbox-authority",
        help="replay and verify synthetic sandbox + authority evidence",
    )
    sandbox_verify.add_argument("--evidence-dir", required=True)
    sandbox_verify.set_defaults(handler=_verify_sandbox_authority)

    artex_chain = subparsers.add_parser(
        "challenge-artex-chain",
        help="qualify inert ARTEX-inspired reconnaissance-to-effect attack chains",
    )
    artex_chain.add_argument("--output-dir", required=True, help="fresh local evidence directory")
    artex_chain.set_defaults(handler=_challenge_artex_chain)

    artex_verify = subparsers.add_parser(
        "verify-artex-chain", help="independently replay synthetic ARTEX-chain evidence",
    )
    artex_verify.add_argument("--evidence-dir", required=True)
    artex_verify.set_defaults(handler=_verify_artex_chain)

    for name, help_text in (
        ("challenge-cursorial", "qualify synthetic causal chains or inspect a selected fictional capture"),
        ("verify-cursorial", "replay and verify a complete Cursorial evidence bundle"),
    ):
        cursorial = subparsers.add_parser(name, help=help_text)
        cursorial.add_argument("--chain", help="explicit local fictional chain JSON, also required for its replay")
        cursorial.add_argument("--expected-head", help="independently supplied exact WolfTrap Git commit")
        if name == "verify-cursorial":
            cursorial.add_argument("--evidence-dir", required=True)
        else:
            cursorial.add_argument("--output-dir", required=True, help="fresh local evidence directory")
        cursorial.set_defaults(handler=_cursorial)

    camouflage = subparsers.add_parser(
        "challenge-cloud-camouflage", help="measure offline cloud-C2 blind spots and lookalikes")
    camouflage.add_argument("--output-dir", required=True, help="fresh local evidence directory")
    camouflage.set_defaults(handler=_challenge_cloud_camouflage)

    camouflage_verify = subparsers.add_parser(
        "verify-cloud-camouflage", help="independently verify camouflage challenge artifacts")
    camouflage_verify.add_argument("--evidence-dir", required=True)
    camouflage_verify.set_defaults(handler=_verify_cloud_camouflage)

    authority = subparsers.add_parser(
        "challenge-cloud-authority", help="test synthetic independent authority after cloud advisories")
    authority.add_argument("--output-dir", required=True, help="fresh local evidence directory")
    authority.set_defaults(handler=_challenge_cloud_authority)

    authority_verify = subparsers.add_parser(
        "verify-cloud-authority", help="replay synthetic cloud authority and verify saved evidence")
    authority_verify.add_argument("--evidence-dir", required=True)
    authority_verify.set_defaults(handler=_verify_cloud_authority)

    cloud_trace = subparsers.add_parser(
        "scan-cloud-trace", help="inspect local pre-sanitized GitHub event metadata offline")
    cloud_trace.add_argument("--root", required=True, help="authorized local input directory")
    cloud_trace.add_argument("--file", required=True, help="simple .json input filename")
    cloud_trace.add_argument("--output-dir", required=True, help="fresh evidence directory outside root")
    cloud_trace.set_defaults(handler=_scan_cloud_trace)

    cloud_trace_verify = subparsers.add_parser(
        "verify-cloud-trace", help="recheck saved cloud trace evidence against its source")
    cloud_trace_verify.add_argument("--root", required=True)
    cloud_trace_verify.add_argument("--file", required=True)
    cloud_trace_verify.add_argument("--evidence-dir", required=True)
    cloud_trace_verify.set_defaults(handler=_verify_cloud_trace)

    agent_challenge = subparsers.add_parser("challenge-agent", help="run independently labelled synthetic agent cases")
    agent_challenge.add_argument("--seed", type=int, default=20261115)
    agent_challenge.add_argument("--output-dir", required=True)
    agent_challenge.set_defaults(handler=_challenge_agent)

    agent_verify = subparsers.add_parser("verify-agent-challenge", help="verify saved agent challenge evidence")
    agent_verify.add_argument("--evidence-dir", required=True)
    agent_verify.set_defaults(handler=_verify_agent_challenge)

    agent_replay = subparsers.add_parser("replay-agent-challenge", help="re-execute verified saved synthetic agent cases")
    agent_replay.add_argument("--evidence-dir", required=True)
    agent_replay.add_argument("--output-dir", required=True)
    agent_replay.set_defaults(handler=_replay_agent_challenge)

    gt_vsa = subparsers.add_parser("challenge-gt-vsa", help="qualify a synthetic vehicle fleet offline")
    gt_vsa.add_argument("--seed", type=int, default=20261117)
    gt_vsa.add_argument("--vehicles", type=int, default=1024)
    gt_vsa.add_argument("--output-dir", type=Path, required=True, help="fresh local evidence directory")
    gt_vsa.set_defaults(handler=_challenge_gt_vsa)

    gt_vsa_verify = subparsers.add_parser("verify-gt-vsa", help="reproduce saved synthetic vehicle evidence")
    gt_vsa_verify.add_argument("--evidence-dir", type=Path, required=True)
    gt_vsa_verify.set_defaults(handler=_verify_gt_vsa)

    challenge = subparsers.add_parser(
        "challenge-build",
        help="run a bounded offline evasion tournament against WolfTrap's own detector",
    )
    challenge.add_argument("--seed", type=int, default=20261115)
    challenge.add_argument("--cases", type=int, default=128)
    challenge.add_argument("--output-dir", required=True, help="fresh directory for replayable synthetic evidence")
    challenge.set_defaults(handler=_challenge_build)

    verification = subparsers.add_parser(
        "verify-challenge", help="verify saved offline challenge hashes and replay inputs"
    )
    verification.add_argument("--evidence-dir", required=True)
    verification.set_defaults(handler=_verify_challenge)

    listing = subparsers.add_parser("list-scenarios", help="list local corpus entries")
    listing.add_argument("--scenario-directory")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(handler=_list_scenarios)

    reproduce = subparsers.add_parser(
        "reproduce", help="replay the exact minimized case saved with a finding"
    )
    reproduce.add_argument("--report", required=True)
    reproduce.add_argument("--finding-id", required=True)
    reproduce.add_argument("--output-dir", default="reports/reproduction")
    reproduce.set_defaults(handler=_reproduce)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
        return int(arguments.handler(arguments))
    except Exception as exc:
        print(f"wolftrap: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
