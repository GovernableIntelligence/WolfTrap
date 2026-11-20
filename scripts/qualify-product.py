"""Qualify the installed artifact with an authored oracle and measured clean first runs."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = ("quickscan.json", "quickscan.md", "quickscan.sarif", "quickscan.manifest.json")


def need(test, message):
    if not test:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def execute(argv, cwd, *, code=0, source=False):
    """wait4 reports this invocation's CPU and peak RSS. Capture output outside the target."""
    env = {"PATH": os.defpath, "LC_ALL": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
    if source:
        env["PYTHONPATH"] = str(ROOT / "src")
    with tempfile.TemporaryFile() as log:
        start = time.monotonic()
        p = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            while True:
                pid, status, usage = os.wait4(p.pid, os.WNOHANG)
                if pid:
                    p.returncode = os.waitstatus_to_exitcode(status)
                    break
                need(time.monotonic() - start < 180, "qualification command timeout")
                time.sleep(0.005)
        finally:
            if p.returncode is None:
                p.kill()
                p.wait()
        elapsed = time.monotonic() - start
        log.seek(0)
        output = log.read(2_000_000).decode("utf-8", errors="replace")
    if p.returncode != code:
        print(output[-2500:], file=sys.stderr)
        raise ValueError(f"unexpected exit {p.returncode}; expected {code} for {Path(argv[0]).name}")
    return output, {"wall_seconds": round(elapsed, 4), "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 4),
                    "peak_rss_kib": usage.ru_maxrss}


def independent_demo(out, head, tree):
    demo = out / "demo"
    report, manifest = read(demo / MEMBERS[0]), read(demo / MEMBERS[-1])
    need(set(manifest["files"]) == set(MEMBERS[:-1]) and {p.name for p in demo.iterdir()} == set(MEMBERS), "bundle membership")
    for name, ref in manifest["files"].items():
        raw = (demo / name).read_bytes()
        need(ref == {"sha256": sha(raw), "bytes": len(raw)}, "archived file integrity")
    build = report["build"]
    need(build == manifest["build"] and (build["commit"], build["tree"]) == (head, tree), "source binding")
    expected = {}
    for name in ("README.md", "review.js"):
        raw = (ROOT / "src/wolftrap/data/product-demo" / name).read_bytes()
        expected[sha(name.encode())] = sha(raw)
    need({f["source_id"]: f["sha256"] for f in report["files"]} == expected, "independent input digests")
    f, = report["findings"]
    need((f["rule_id"], f["line"], f["source_id"]) == ("WT-AGENT-002", 2, sha(b"review.js"))
         and report["status"] == manifest["status"] == "REVIEW_REQUIRED" and not report["enforced"]
         and report["conclusive_runtime_observations"] == 0, "independent location, status or scope")
    need(read(demo / MEMBERS[2])["runs"][0]["results"][0]["ruleId"] == f["rule_id"], "SARIF binding")


def qualify_cases(cli, outside, root):
    spec = importlib.util.spec_from_file_location("authored_cases", ROOT / "tests/product_cases.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    results, cases = {}, []
    for name, group, filename, source, code, expected in oracle.CASES:
        project = root / ("case-" + name)
        project.mkdir()
        file = project / filename
        file.write_text(source)
        output = root / ("result-" + name)
        execute([cli, "quickscan", "--root", project, "--output-dir", output], outside, code=code)
        execute([cli, "verify-report", "--root", project, "--evidence-dir", output], outside, code=2 if code == 2 else 0)
        r = read(output / MEMBERS[0])
        actual = [(f["rule_id"], f["line"]) for f in r["findings"]]
        results[name] = {"INCONCLUSIVE": 2, "NO_PATTERN_MATCH": 0, "REVIEW_REQUIRED": 1}[r["status"]], actual
        if r["files"]:
            row, = r["files"]
            need((row["source_id"], row["sha256"]) == (sha(filename.encode()), sha(file.read_bytes())), "case inventory")
        cases.append({"id": name, "group": group, "status": r["status"], "expected": expected, "observed": actual})
    need(not oracle.mismatches(results), "independent control mismatch")
    defective = {"always-clear": {k: (0, []) for k in results}, "always-review": {k: (1, []) for k in results},
                 "incomplete-is-clear": {k: (0, []) if v[0] == 2 else v for k, v in results.items()}}
    witnesses = {name: oracle.mismatches(result) for name, result in defective.items()}
    need(all(witnesses.values()), "undetected defective implementation")
    return {"cases": cases, "mismatches": 0, "counterexamples": witnesses}


def qualify(args):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    def clean():
        return not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    need(head == args.expected_head and clean(), "require a clean exact source revision")
    need(os.readlink("/proc/self/ns/net") != args.parent_netns and {n for _, n in socket.if_nameindex()} == {"lo"},
         "require a dedicated loopback-only network namespace")
    out = args.output_dir.absolute()
    need(out == out.resolve() and not out.is_relative_to(ROOT), "fresh external output required")
    out.mkdir(mode=0o700)
    execute([sys.executable, "-m", "wolftrap.test_runner", "--pattern", "test_product*.py", "--output", out / "unit-tests.json"],
            ROOT, source=True)
    unit = read(out / "unit-tests.json")
    need(unit["tests_run"] >= 19 and unit["successful"] and unit["source_revision"]["commit_sha"] == head and
         not any(unit[k] for k in ("failures", "errors", "expected_failures", "unexpected_successes", "skipped")), "unit qualification")
    samples = []
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        for dest in (out / "kit", base / "second"):
            execute([sys.executable, "-I", ROOT / "scripts/build-product.py", "--expected-head", head,
                     "--wheelhouse", args.wheelhouse.absolute(), "--output-dir", dest], ROOT)
        kit = out / "kit"
        wheel, = kit.glob("*.whl")
        pin = sha(wheel.read_bytes())
        need({p.name for p in kit.iterdir()} == {wheel.name, "SHA256SUMS", "core.cdx.json"} and
             all(p.read_bytes() == (base / "second" / p.name).read_bytes() for p in kit.iterdir()), "independent rebuild bytes")
        need((pin + "  " + wheel.name) in (kit / "SHA256SUMS").read_text().splitlines(), "wheel checksum")
        lock = base / "install.txt"
        lock.write_text("wolftrap==0.5.4.dev1 --hash=sha256:" + pin + "\n")
        neutral = base / "outside"
        neutral.mkdir()
        for i in range(3):
            start = time.monotonic()
            env = base / ("install-" + str(i))
            execute([sys.executable, "-I", "-m", "venv", env], neutral)
            python, cli = env / "bin/python", env / "bin/wolftrap"
            install = [python, "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir",
                       "--no-index", "--no-deps", "--only-binary=:all:", "--require-hashes", "--find-links", kit, "-r"]
            _, install_metrics = execute([*install, lock], neutral)
            state, doctor_metrics = execute([cli, "doctor", "--json"], neutral)
            doctor = json.loads(state)
            need(doctor["ready"] and doctor["build"]["commit"] == head and doctor["build"]["tree"] == tree, "installed provenance")
            target = out / "demo" if i == 0 else base / ("demo-" + str(i))
            _, scan_metrics = execute([cli, "quickscan", "--demo", "--output-dir", target], neutral, code=1)
            first = time.monotonic() - start
            _, replay_metrics = execute([cli, "verify-report", "--demo", "--evidence-dir", target, "--manifest-sha256",
                                         sha((target / MEMBERS[-1]).read_bytes())], neutral)
            samples.append({"install_to_first_completed_scan_seconds": round(first, 4),
                            "install_to_verified_report_seconds": round(time.monotonic() - start, 4),
                            "install": install_metrics, "doctor": doctor_metrics, "scan": scan_metrics, "replay": replay_metrics})
            need(all((target / n).read_bytes() == (out / "demo" / n).read_bytes() for n in MEMBERS), "clean-install replay")
            if i == 0:
                save(out / "doctor.json", doctor)
                controls = qualify_cases(cli, neutral, base)
                save(out / "controls.json", controls)
                # A canary project shadows a stdlib name and contains Python startup hooks.
                # The installed executable must treat these as unsupported files without importing them.
                project = base / "authorized-project"
                project.mkdir()
                canary = project / "executed"
                for name in ("json.py", "sitecustomize.py"):
                    (project / name).write_text("from pathlib import Path\nPath(" + repr(str(canary)) + ").touch()\n")
                doc = project / "readme.md"
                doc.write_text("Local user guide.")
                checks = base / "project-report"
                execute([cli, "quickscan", "--root", project, "--file", doc.name, "--output-dir", checks], project)
                execute([cli, "verify-report", "--root", project, "--file", doc.name, "--evidence-dir", checks], project)
                need(not canary.exists(), "target code executed")
                (checks / "quickscan.md").write_text("altered")
                execute([cli, "verify-report", "--root", project, "--file", doc.name, "--evidence-dir", checks], project, code=2)
                # Exercise the documented read budget on eight full-size benign files.
                batch = base / "bounded"
                batch.mkdir()
                for j in range(8):
                    (batch / f"guide{j}.md").write_bytes((b"Calendar guide.\n" * 2048))
                _, bulk = execute([cli, "quickscan", "--root", batch, "--output-dir", base / "batch-report"], neutral)
                need(read(base / "batch-report/quickscan.json")["coverage"]["bytes_read"] == 262144, "benchmark workload")
                site = Path(execute([python, "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], neutral)[0].strip())
                installed = site / "wolftrap/agent_rules.py"
                with installed.open("ab") as stream:
                    stream.write(b"\n# fictional local drift\n")
                blocked, _ = execute([cli, "doctor", "--json"], neutral, code=2)
                need(json.loads(blocked)["reason"] == "installed-member-changed", "modified installation treated as ready")
                execute([cli, "quickscan", "--demo", "--output-dir", base / "should-not-exist"], neutral, code=2)
                need(not (base / "should-not-exist").exists(), "write from untrusted install")
            execute([python, "-I", "-m", "pip", "--isolated", "uninstall", "-y", "wolftrap"], neutral)
            need(not cli.exists(), "uninstall left an entry point")
            bad = base / "wrong-pin.txt"
            bad.write_text("wolftrap==0.5.4.dev1 --hash=sha256:" + "0" * 64 + "\n")
            execute([*install, bad], neutral, code=1)
            need(not cli.exists(), "wrong pin installed")
    independent_demo(out, head, tree)
    need(clean(), "qualification changed the source")
    osinfo = platform.freedesktop_os_release()
    save(out / "qualification.json", {"schema": "wolftrap.product-qualification/v1", "status": "PASSED_BOUNDED",
         "commit": head, "tree": tree, "wheel_sha256": pin, "wheel_bytes": wheel.stat().st_size,
         "source_guard_scope": "tracked source and selected redacted reports; wheel checked against source and RECORD",
         "environment": {"os": osinfo["ID"], "os_version": osinfo["VERSION_ID"], "architecture": platform.machine(),
                         "python": platform.python_version(), "logical_cpus_available": len(os.sched_getaffinity(0))},
         "loopback_only": True, "clean_install_samples": samples, "bounded_256_kib_scan": bulk,
         "timing_scope": "local wheel and prepared Python through first demo result; no download or human interaction",
         "unit_tests": unit["tests_run"], "authored_controls": len(controls["cases"]),
         "defective_controls_caught": len(controls["counterexamples"]), "independent_rebuilds": 2,
         "complete_demo_replays": 3, "human_usability_pilot": "NOT TESTED", "publisher_authentication": "BLOCKED"})
    reports = ["qualification.json", "doctor.json", "controls.json", "unit-tests.json", "kit/core.cdx.json",
               *("demo/" + n for n in MEMBERS)]
    execute([sys.executable, "-m", "wolftrap.public_guard", head, "--report-root", out,
             *(s for n in reports for s in ("--report", n))], ROOT, source=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-head", required=True)
    p.add_argument("--wheelhouse", required=True, type=Path)
    p.add_argument("--parent-netns", required=True)
    p.add_argument("--output-dir", required=True, type=Path)
    qualify(p.parse_args())
