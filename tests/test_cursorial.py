import ast
import inspect
import json
import socket
import subprocess
import unittest
from copy import deepcopy
from unittest.mock import patch

from wolftrap import cursorial_oracle
from wolftrap.canonical import sha256_json
from wolftrap.cursorial import MUTANTS, STATIC, UNKNOWN, VERIFIED, assess, confirm, inspect_capture, qualify
from wolftrap.cursorial_corpus import CORRUPTIONS, VARIANTS, cases, corrupt, fixture, vary
from wolftrap.cursorial_lab import EffectWitness, execute, schedule
from wolftrap.cursorial_trace import LIMITS, Gap, decode, track, validate


class CursorialHostileTests(unittest.TestCase):
    def test_complete_corpus_asserts_benign_adversarial_and_incomplete_cases_separately(self):
        with patch.object(socket, "socket", side_effect=AssertionError), patch.object(
                subprocess, "Popen", side_effect=AssertionError):
            report, archive = qualify()
        self.assertEqual(report["status"], "PASSED_BOUNDED")
        self.assertEqual(report["summary"]["cases"], 156)
        self.assertEqual(len(archive["cases"]), len({c["id"] for c in report["cases"]}))
        self.assertEqual(report["summary"]["by_classification"], {VERIFIED: 104, STATIC: 4, UNKNOWN: 48})
        self.assertTrue(all(c["matched"] for c in report["cases"]))
        for c, record in zip(report["cases"], archive["cases"], strict=True):
            self.assertEqual(c["input_sha256"], sha256_json(record["trace"]))
            if c["graph"] is not None:
                validate(c["graph"], "graph")

    def test_oracle_reconstructs_scope_without_importing_control_or_ledger(self):
        code = ast.parse(inspect.getsource(cursorial_oracle))
        self.assertEqual({n.names[0].name for n in ast.walk(code) if isinstance(n, ast.Import)}, {"hashlib", "json"})
        self.assertFalse(any(isinstance(n, ast.ImportFrom) for n in ast.walk(code)))
        reference = cursorial_oracle.reference
        events = track(execute(fixture(3, "lost-reply"))).events
        expected = reference(events)
        for e in events:
            if e["kind"] == "effect_observed":
                e["records"] = []
            elif e["kind"] == "gate_decision":
                e["decision"] = "allow"
            elif e["kind"] == "agent_proposal":
                e["claim"] = "approved"
        self.assertEqual(reference(events), expected)
        self.assertEqual([len(r["records"]) for r in expected], [1, 0])

    def test_valid_foreign_grant_is_rejected_only_outside_its_bound_scope(self):
        for variant, field in (("foreign-tenant", "tenant"), ("chain-splice", "grant_chain")):
            plan = vary(fixture(0), variant)
            local, foreign = [e for e in plan if e["kind"] == "grant_state"]
            self.assertNotEqual(local["grant"], foreign["grant"])
            self.assertNotEqual(local[field], foreign[field])
            self.assertEqual(local["digest"], foreign["digest"])
            self.assertEqual(foreign["state"], "active")
            probe = next(e for e in plan if e["kind"] == "agent_proposal")
            self.assertEqual(probe["grant"], foreign["grant"])
            denied = assess(execute(plan))
            self.assertEqual(denied["classification"], VERIFIED)
            self.assertEqual(denied["witnesses"][0]["host_witness"]["commit"], "deny")
            # The registry entry is independently usable in its actual fictional context.
            if variant == "foreign-tenant":
                for event in plan:
                    if event["kind"] in ("chain_opened", "request_bound"):
                        event["tenant"] = foreign["tenant"]
            else:
                for event in plan:
                    event["chain"] = foreign["grant_chain"]
            w = assess(execute(plan))["witnesses"][0]
            self.assertEqual((w["host_witness"]["commit"], len(w["ledger_witness"]["records"])), ("allow", 1))

    def test_graph_retains_multihop_lineage_boundary_and_recovery_provenance(self):
        doc = execute(fixture(3, "lost-reply"))
        tracked = track(doc)
        self.assertEqual(tracked.graph, track(json.loads(json.dumps(doc, sort_keys=True))).graph)
        relation = {e["relation"] for e in tracked.graph["edges"]}
        self.assertTrue({"delegation", "epoch", "grant", "definition", "proposal", "binding", "prepare",
                         "commit", "ledger-prefix", "previous-slot", "recovery", "completion"} <= relation)
        times = {n["id"]: n["at"] for n in tracked.graph["nodes"]}
        self.assertTrue(all(times[e["from"]] < times[e["to"]] for e in tracked.graph["edges"]))
        self.assertEqual(execute(schedule(tracked)), doc)

    def test_expiry_or_epoch_change_invalidates_even_prepared_delegation(self):
        plan = fixture(3)
        commit = next(e for e in plan if e.get("phase") == "commit")
        next(e for e in plan if e["kind"] == "delegation_observed")["expires"] = commit["at"]
        w = assess(execute(plan))["witnesses"][0]
        self.assertEqual((w["oracle"]["prepare"], w["host_witness"]["commit"], w["ledger_witness"]["records"]),
                         ("allow", "deny", []))
        for case in ("epoch-during-execution", "expires-at-commit"):
            row = assess(execute(fixture(1, case)))["witnesses"][0]
            self.assertEqual((row["oracle"]["prepare"], row["oracle"]["commit"]), ("allow", "deny"))

    def test_legitimate_upgrade_separate_operation_and_delegation_all_succeed(self):
        for p in range(4):
            for family, count in (("approved-upgrade", 1), ("renewed", 1), ("two-operations", 2)):
                r = assess(execute(fixture(p, family)))
                self.assertEqual(r["classification"], VERIFIED)
                self.assertEqual(r["advisories"], [])
                self.assertEqual(sum(len(w["ledger_witness"]["records"]) for w in r["witnesses"]), count)

    def test_static_claim_never_creates_a_grant_or_a_ledger_write(self):
        doc = execute(fixture(1, "unregistered"))
        doc["sources"]["agent"]["events"][0]["claim"] = "success"
        r = assess(doc)
        self.assertEqual(r["advisories"][0]["classification"], STATIC)
        self.assertEqual(r["witnesses"][0]["ledger_witness"]["records"], [])
        self.assertEqual(r["classification"], VERIFIED)
        doc["sources"]["ledger"]["events"].clear()
        r = assess(doc)
        self.assertEqual((r["classification"], r["witnesses"]), (UNKNOWN, []))
        self.assertEqual(r["advisories"][0]["classification"], STATIC)

    def test_catalog_and_agent_cannot_supply_a_host_or_ledger_witness(self):
        for witness in ("grant_state", "gate_decision", "request_bound", "effect_observed", "delegation_observed"):
            doc = execute(fixture(1))
            src = doc["sources"]["ledger" if witness == "effect_observed" else "host"]["events"]
            event = next(e for e in src if e["kind"] == witness)
            src.remove(event)
            doc["sources"]["agent"]["events"].append(event)
            self.assertEqual(assess(doc)["reason"], "invalid-witness-source-or-kind")
        doc = execute(fixture(0))
        doc["sources"]["ledger"]["alias"] = doc["sources"]["host"]["alias"]
        self.assertEqual(assess(doc)["classification"], UNKNOWN)

    def test_orphan_spliced_reordered_and_incomplete_witnesses_fail_closed(self):
        for name, reason in CORRUPTIONS.items():
            with self.subTest(name=name):
                result = assess(corrupt(execute(fixture(2)), name))
                self.assertEqual((result["classification"], result["reason"]), (UNKNOWN, reason))
        for kind in ("tick", "cycle", "spliced-window", "generation", "unfinished-recovery"):
            doc = execute(fixture(2, "lost-reply"))
            host = doc["sources"]["host"]["events"]
            if kind == "tick":
                host[1]["at"] = host[0]["at"]
            elif kind == "cycle":
                link = next(e for e in host if e["kind"] == "delegation_observed")
                link["parent"] = link["id"]
            elif kind == "spliced-window":
                w1, w2 = doc["sources"]["ledger"]["events"]
                w2["commit"] = w1["commit"]
            elif kind == "generation":
                host[-1]["attempts"] -= 1
            else:
                host.remove(next(e for e in host if e.get("phase") == "resumed"))
            self.assertEqual(assess(doc)["classification"], UNKNOWN)

    def test_complete_empty_ledger_differs_from_missing_witness_and_fabricated_success(self):
        plan = fixture(1)
        missing = assess(corrupt(execute(plan), "missing-ledger"))
        self.assertEqual((missing["classification"], missing["discrepancies"]), (UNKNOWN, []))
        with patch.object(EffectWitness, "apply", return_value=None):
            forged = assess(execute(plan))
        self.assertEqual(set(forged["discrepancies"][0]["differences"]), {"records"})
        self.assertEqual(forged["witnesses"][0]["host_witness"]["commit"], "allow")
        self.assertEqual(forged["witnesses"][0]["ledger_witness"]["records"], [])

    def test_expected_vs_actual_payload_catches_substitution_even_at_the_same_count(self):
        r = assess(execute(fixture(1), "wrong-tool-effect"))
        w = r["witnesses"][0]
        self.assertEqual(len(w["oracle"]["records"]), len(w["ledger_witness"]["records"]))
        self.assertNotEqual(w["oracle"]["records"][0]["operation"], w["ledger_witness"]["records"][0]["operation"])
        self.assertEqual(set(r["discrepancies"][0]["differences"]), {"records"})

    def test_every_defect_has_fresh_reproduction_and_a_smaller_executable_counterexample(self):
        r, _ = qualify()
        self.assertEqual({m["mutant"] for m in r["mutants"]}, MUTANTS.keys())
        for m in r["mutants"]:
            proof = m["reproduction"]
            self.assertTrue(m["caught"])
            self.assertLess(proof["minimized_events"], proof["original_events"])
            self.assertTrue(proof["single_deletion_search_complete"])
            self.assertEqual(proof["minimized_schedule_sha256"], sha256_json(proof["minimized_schedule"]))
            self.assertEqual(proof["initial_replays"], [proof["fingerprint"]] * 2)
            for replay in proof["minimized_replays"]:
                self.assertEqual(replay["fingerprint"], proof["fingerprint"])
            replay = assess(execute(proof["minimized_schedule"], m["mutant"]))
            self.assertEqual(replay["discrepancies"][0]["fingerprint"], proof["fingerprint"])

    def test_intermittence_cannot_confirm_or_create_a_minimized_effect(self):
        sequence = iter(("fake-success", "correct", "fake-success"))
        r = confirm(fixture(0), lambda: next(sequence))
        self.assertEqual(r["classification"], UNKNOWN)
        self.assertIn(None, r["initial_replays"])
        self.assertNotIn("minimized_schedule", r)

    def test_blanket_controls_fail_through_the_normal_qualification_path(self):
        for control in ("always-deny", "always-allow", "fake-success"):
            report, _ = qualify(control)
            self.assertEqual(report["exit_code"], 1)
            self.assertGreater(report["summary"]["mismatches"], 0)
        for answer in (True, False):
            report, _ = qualify(alert_detector=lambda _: answer)
            self.assertEqual(report["exit_code"], 1)

    def test_variations_are_derived_from_the_recorded_operation_and_repeat_exactly(self):
        plan = fixture(3)
        original = deepcopy(plan)
        for variant in VARIANTS:
            self.assertEqual(vary(plan, variant), vary(plan, variant))
            self.assertNotEqual(sha256_json(plan), sha256_json(vary(plan, variant)))
        self.assertEqual(original, plan)
        selected = inspect_capture(execute(plan))
        self.assertEqual(selected["fresh_capture_sha256"], [sha256_json(execute(plan))] * 2)
        self.assertEqual({p["variation"] for p in selected["pursuit"]}, set(VARIANTS))
        self.assertEqual(selected["pursuit_gaps"], 0)

    def test_recorded_disagreement_is_not_repeated_as_a_fresh_effect(self):
        doc = execute(fixture(1, "inactive"), "effect-on-deny")
        result = inspect_capture(doc)
        self.assertEqual(result["status"], UNKNOWN)
        self.assertEqual(result["capture"]["reason"], "selected-capture-not-reproduced")
        self.assertNotIn(sha256_json(doc), result["fresh_capture_sha256"])

    def test_unavailable_mutation_window_is_explicit(self):
        plan = fixture(1)
        for index, e in enumerate(plan):
            e["at"] = index
        r = inspect_capture(execute(plan))
        self.assertEqual(r["capture"]["classification"], VERIFIED)
        self.assertEqual(r["status"], UNKNOWN)
        self.assertGreater(r["pursuit_gaps"], 0)

    def test_json_ambiguity_unsupported_fields_and_resource_bounds(self):
        for raw in (b'{"a":0,"\\u0061":1}', b'\xff', b'1.0', b'NaN', b'['*14+b']'*14,
                    b'['+b'0,'*5000+b'0]', b' '*100000):
            with self.assertRaises(Gap):
                decode(raw)
        for key, value in (("tenant", True), ("owner", "https://example.org"), ("epoch", 10000),
                           ("raw_prompt", "fictional text")):
            doc = execute(fixture(1))
            doc["sources"]["host"]["events"][0][key] = value
            self.assertEqual(assess(doc)["classification"], UNKNOWN)
        doc = execute(fixture(0))
        doc["sources"]["host"]["events"][-1]["at"] = 4094
        self.assertEqual(assess(doc)["reason"], "logical-window-limit")
        with self.assertRaisesRegex(Gap, "event-count-limit"):
            execute([{}] * (LIMITS["events"] + 1))

    def test_known_miss_and_benign_lookalike_measure_their_declared_boundary(self):
        by_id = {c.id: c for c in cases()}
        self.assertEqual(execute(by_id["indistinguishable-session-1"].plan), execute(by_id["baseline-1"].plan))
        r = assess(execute(by_id["glossary-lookalike-1"].plan))
        self.assertTrue(r["advisories"])
        self.assertEqual(r["witnesses"][0]["ledger_witness"]["after"], 1)
