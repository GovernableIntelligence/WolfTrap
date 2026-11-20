"""Human and machine interfaces for the free offline product profile."""

import json
import platform
import sys

from .agent_scan import _sha
from .product_files import MEMBERS, ProductError, check_root, deliver, disjoint, local_path, selection
from .product_install import PACKAGE, VERSION, readiness
from .product_scan import ACTIONS, TITLES, analyze, render

HELP = {
    "unsupported-platform": "Use the tested Linux CPython 3.12 profile listed in the offline product guide.",
    "missing-or-unreadable-build-record": "Install the hash-checked candidate wheel in a clean virtual environment.",
    "installed-member-changed": "Replace this environment with a fresh installation from the independently pinned wheel.",
    "invalid-build-record": "Reinstall from the independently pinned wheel.",
    "choose-fresh-output": "Choose a new directory name under an existing trusted parent. Previous evidence was preserved.",
    "overlapping-evidence": "Choose an evidence directory outside the selected project.",
    "untrusted-evidence-parent": "Use a private output parent that you own, or the system temporary directory.",
    "unsafe-path": "Use an ordinary local path with no symlinks, parent traversal or URI.",
    "private-or-system-root": "Select a project directory outside private stores, the home root and system directories.",
    "invalid-selection": "Use distinct supported root-relative file names outside excluded directories.",
    "manifest-pin-mismatch": "Check the retained manifest digest, selected source and installed version.",
    "evidence-mismatch": "The source or evidence differs. Preserve the original and inspect a fresh scan.",
    "input-unavailable": "Check local permissions, symlinks and the existing parent of the evidence directory.",
}


def configure(parser, subparsers):
    parser.add_argument("--version", action="version", version="WolfTrap " + VERSION)
    doctor = subparsers.add_parser("doctor", help="check the offline product installation and filesystem prerequisites")
    rules = subparsers.add_parser("list-rules", help="list the seven quickscan rules and their review guidance")
    for command in (doctor, rules):
        command.add_argument("--json", action="store_true", help="print machine-readable information")
        command.set_defaults(handler=run)
    for name, help_text, location in (("quickscan", "inspect a local authorized project without executing it", "output-dir"),
                                      ("verify-report", "regenerate quickscan evidence from the original local scope", "evidence-dir")):
        p = subparsers.add_parser(name, help=help_text, description=help_text + ". " + (
            "Exit 0 for a covered no-match, 1 for review, 2 for incomplete input or errors." if name == "quickscan"
            else "Exit 0 for replay of a complete result and 2 for incomplete or mismatched evidence."))
        source = p.add_mutually_exclusive_group(required=True)
        source.add_argument("--root", help="local project you own or are authorized to inspect")
        source.add_argument("--demo", action="store_true", help="select the installed two-file fictional example")
        p.add_argument("--file", action="append", help="limit scope to a root-relative file (repeatable)")
        p.add_argument("--" + location, required=True, help="fresh sibling directory under an existing parent" if name == "quickscan"
                       else "existing quickscan evidence directory")
        p.add_argument("--show-paths", action="store_true", help="show escaped root-relative names locally on stdout")
        if name == "verify-report":
            p.add_argument("--manifest-sha256", help="optional independent pin of the original manifest bytes")
        p.set_defaults(handler=run)


def run(args):
    if args.command == "list-rules":
        rows = {rule: {"meaning": title, "next_action": ACTIONS[rule]} for rule, title in TITLES.items()}
        print(json.dumps(rows, sort_keys=True) if args.json else "\n".join(f"{k}  {v['meaning']}" for k, v in rows.items()))
        return 0
    state = readiness()
    if args.command == "doctor":
        info = {**state, "schema": "wolftrap.doctor/v1", "version": VERSION,
                "system": platform.system(), "architecture": platform.machine(), "python": platform.python_version(),
                "next_action": "Run wolftrap quickscan --help to select a local project or the demo." if state["ready"]
                else HELP.get(state["reason"], "Check the offline installation and supported platform.")}
        if args.json:
            print(json.dumps(info, sort_keys=True))
        else:
            print(f"WolfTrap {VERSION} | {info['system']} {info['architecture']} | Python {info['python']}")
            print(("READY" if state["ready"] else "INCONCLUSIVE") + " · " + state["reason"])
            if state["build"]:
                print("Installed source " + state["build"]["commit"] + " · tree " + state["build"]["tree"])
            print(info["next_action"])
        return 0 if state["ready"] else 2
    try:
        if not state["ready"]:
            raise ProductError(state["reason"])
        replay = args.command == "verify-report"
        root = local_path(PACKAGE / "data/product-demo" if args.demo else args.root)
        check_root(root)
        dest = local_path(args.evidence_dir if replay else args.output_dir)
        selected = selection(args.file)
        disjoint(root, dest)
        report, paths = analyze(root, selected, state["build"])
        files = render(report)
        deliver(dest, files, replay=replay, expected_pin=getattr(args, "manifest_sha256", None), source_root=root)
        status = report["status"]
        print(("REPRODUCED " if replay else "") + status + f" · {len(report['files'])} selected files, "
              f"{len(report['findings'])} static review signals.")
        for f in report["findings"]:
            print(f"{f['rule_id']} · {TITLES[f['rule_id']]} · source {f['source_id']} line {f['line']}")
        if args.show_paths:
            for identifier, path in sorted(paths.items()):
                print(identifier + "  " + json.dumps(path, ensure_ascii=True))
        if report["incomplete"]:
            print("Coverage gaps: " + ", ".join(report["incomplete"]))
        if any(f["incomplete"] for f in report["files"]):
            print("See the per-file coverage reasons in quickscan.md.")
        print(report["next_action"])
        print("Read quickscan.md in your evidence directory. Manifest SHA-256 " + _sha(files[MEMBERS[-1]]))
        return 2 if status == "INCONCLUSIVE" else int(status == "REVIEW_REQUIRED" and not replay)
    except (ValueError, OSError) as exc:
        reason = str(exc) if isinstance(exc, ProductError) else "input-unavailable"
        print("INCONCLUSIVE · " + reason + ". " + HELP.get(reason, "Check the original selection, evidence and file permissions."),
              file=sys.stderr)
        return 2
