import contextlib
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import cursorial_evidence as evidence
from wolftrap.cli import main
from wolftrap.cursorial_corpus import fixture
from wolftrap.cursorial_lab import execute
from wolftrap.cursorial_trace import Gap


class CursorialEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        inputs = self.root / "inputs"
        inputs.mkdir()
        self.path = inputs / "trace.json"
        self.doc = execute(fixture(1))
        self.path.write_text(json.dumps(self.doc))
        self.out = self.root / "evidence"

    def cli(self, verify=False, selected=True, dest=None, extra=()):
        args = ["verify-cursorial" if verify else "challenge-cursorial"]
        args.extend(("--evidence-dir" if verify else "--output-dir", str(dest or self.out)))
        if selected:
            args.extend(("--chain", str(self.path)))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main([*args, *extra])
        return code, output.getvalue()

    def test_both_cli_modes_replay_all_artifacts_and_reject_interchange(self):
        for selected, directory in ((False, self.out), (True, self.root / "other")):
            self.assertEqual(self.cli(selected=selected, dest=directory)[0], 0)
            self.assertEqual(self.cli(True, selected=selected, dest=directory)[0], 0)
            self.assertEqual(set(evidence.MEMBERS), {p.name for p in directory.iterdir()})
            self.assertEqual(self.cli(True, selected=not selected, dest=directory)[0], 2)

    def test_all_reports_and_unsigned_manifest_are_reproduced_independently(self):
        self.assertEqual(self.cli(selected=False)[0], 0)
        second = self.root / "second"
        self.assertEqual(self.cli(selected=False, dest=second)[0], 0)
        manifest = json.loads((self.out / evidence.MEMBERS[-1]).read_bytes())
        self.assertEqual(manifest["state"], "COMPLETE")
        for n in evidence.MEMBERS:
            raw = (self.out / n).read_bytes()
            self.assertEqual(raw, (second / n).read_bytes())
            if n in manifest["files"]:
                self.assertEqual(manifest["files"][n], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})

    def test_rehashed_forgery_of_each_artifact_and_manifest_fails_replay(self):
        self.assertEqual(self.cli()[0], 0)
        manifest = self.out / "cursorial.manifest.json"
        original = manifest.read_bytes()
        for name in evidence.MEMBERS[:-1]:
            item = self.out / name
            raw = item.read_bytes()
            changed = raw + b" "
            item.write_bytes(changed)
            doc = json.loads(original)
            doc["files"][name] = {"bytes": len(changed), "sha256": hashlib.sha256(changed).hexdigest()}
            manifest.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            self.assertEqual(self.cli(True)[0], 2)
            manifest.write_bytes(original)
            item.write_bytes(raw)
        manifest.write_bytes(original.replace(b'"COMPLETE"', b'"PARTIAL","state":"COMPLETE"'))
        self.assertEqual(self.cli(True)[0], 2)

    def test_exact_head_pinning_and_stale_selected_input(self):
        sha = evidence.source_identity(None)["commit_sha"]
        self.assertEqual(self.cli(extra=("--expected-head", sha))[0], 0)
        self.assertEqual(self.cli(True, extra=("--expected-head", "0"*40))[0], 2)
        self.path.write_bytes(b"\n" + self.path.read_bytes())
        self.assertEqual(self.cli(True, extra=("--expected-head", sha))[0], 2)
        with patch.object(evidence, "repository_root", return_value=self.root):
            self.assertEqual(self.cli(True)[0], 2)
        with patch.object(evidence, "_read_file", return_value=b"uncommitted"):
            with self.assertRaisesRegex(Gap, "tracked-engine-changed"):
                evidence.source_identity(None)

    def test_incomplete_and_static_only_exit_codes_survive_replay(self):
        self.doc["sources"]["ledger"]["events"].clear()
        self.path.write_text(json.dumps(self.doc))
        self.assertEqual(self.cli()[0], 2)
        self.assertEqual(self.cli(True), (2, "VERIFIED_EVIDENCE INCONCLUSIVE\n"))
        doc = execute([{"id": 5, "at": 8, "chain": 1, "kind": "tool_definition_observed",
                        "server": 1, "tool": 1, "schema_rev": 1, "indicator": "approval"}], mode="metadata")
        self.path.write_text(json.dumps(doc))
        other = self.root / "static"
        self.assertEqual(self.cli(dest=other)[0], 1)
        self.assertEqual(self.cli(True, dest=other), (1, "VERIFIED_EVIDENCE STATIC REVIEW SIGNAL\n"))

    def test_input_and_evidence_symlinks_unsafe_paths_and_nonregular_files(self):
        self.path.unlink()
        self.path.symlink_to(self.root / "unavailable")
        self.assertEqual(self.cli()[0], 2)
        self.assertFalse(self.out.exists())
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(self.cli()[0], 2)
        self.path.unlink()
        self.path.write_text(json.dumps(self.doc))
        for dest in (self.path.parent / "out", self.root, self.root / "unused" / ".." / "escaped"):
            self.assertEqual(self.cli(dest=dest)[0], 2)
        parent = self.root / "link-dir"
        parent.symlink_to(self.path.parent, target_is_directory=True)
        self.path = parent / self.path.name
        self.assertEqual(self.cli()[0], 2)
        self.assertFalse(self.out.exists())

    def test_missing_extra_hardlinked_and_symlinked_members_fail_closed(self):
        self.assertEqual(self.cli()[0], 0)
        for name in evidence.MEMBERS:
            path = self.out / name
            raw = path.read_bytes()
            path.unlink()
            self.assertEqual(self.cli(True)[0], 2)
            path.symlink_to(self.path)
            self.assertEqual(self.cli(True)[0], 2)
            path.unlink()
            path.write_bytes(raw)
        link = self.root / "alias"
        link.hardlink_to(self.out / "cursorial.md")
        self.assertEqual(self.cli(True)[0], 2)
        link.unlink()
        (self.out / "extra").touch()
        self.assertEqual(self.cli(True)[0], 2)
        self.assertEqual(self.cli()[0], 2)

    def test_source_changes_during_measurement_leave_no_complete_manifest(self):
        original = evidence.inspect_capture

        def changing(doc):
            r = original(doc)
            self.path.write_text("{}")
            return r

        with patch.object(evidence, "inspect_capture", side_effect=changing):
            self.assertEqual(self.cli()[0], 2)
        self.assertFalse((self.out / "cursorial.manifest.json").exists())

    def test_input_reread_and_report_replacement_during_verification(self):
        self.assertEqual(self.cli()[0], 0)
        original = evidence._member

        def unstable(fd, name, limit):
            raw = original(fd, name, limit)
            if name == "cursorial.sarif":
                (self.out / "cursorial.json").write_text("{}")
            return raw

        with patch.object(evidence, "_member", side_effect=unstable):
            self.assertEqual(self.cli(True)[0], 2)

    def test_malformed_input_is_redacted_and_git_only_reads_the_engine(self):
        marker = "FictionalSensitiveIdentifier"
        self.path.write_text(json.dumps({"command": marker, "raw_prompt": str(self.path)}))
        git_calls = []
        real = subprocess.run

        def guarded(args, **kw):
            self.assertEqual(args[0], "git")
            self.assertIn(args[1], ("rev-parse", "ls-tree"))
            self.assertNotIn(str(self.path), str((args, kw)))
            git_calls.append(args[1])
            return real(args, **kw)

        with patch("subprocess.run", side_effect=guarded), patch.object(socket, "socket", side_effect=AssertionError):
            code, output = self.cli()
        self.assertEqual(code, 2)
        self.assertTrue(git_calls)
        saved = output.encode() + b"".join(p.read_bytes() for p in self.out.iterdir())
        for value in (marker, "raw_prompt", str(self.path)):
            self.assertNotIn(value.encode(), saved)

    def test_output_is_exclusive_and_partial_publication_cannot_verify(self):
        before = self.path.read_bytes()
        real = evidence.os.fsync
        count = 0

        def interrupted(fd):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("synthetic write interruption")
            return real(fd)

        with patch.object(evidence.os, "fsync", side_effect=interrupted):
            self.assertEqual(self.cli()[0], 2)
        self.assertFalse((self.out / "cursorial.manifest.json").exists())
        self.assertEqual(self.cli(True)[0], 2)
        self.assertEqual(self.cli()[0], 2)
        self.assertEqual(before, self.path.read_bytes())
