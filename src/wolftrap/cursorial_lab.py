"""Fictional host and separate append-only effect witness for Cursorial experiments."""

from __future__ import annotations

from copy import deepcopy
from typing import Callable

from .canonical import sha256_json
from .effects import SyntheticEffectLedger
from .cursorial_trace import CHAIN, LIMITS, ROLES, Tracked, need

CONTROLS = ("correct", "always-allow", "always-deny", "claim-is-grant", "omit-identity",
            "skip-final", "forget-slot", "fake-success", "wrong-tool-effect", "effect-on-deny")


class EffectWitness:
    """Read the executor's actual writes. The gate receives only the write callback."""

    def __init__(self) -> None:
        self.ledger = SyntheticEffectLedger()
        self.payloads: dict[str, dict] = {}

    def apply(self, at: int, binding: dict, proposal: dict, operation: dict) -> None:
        payload = deepcopy(operation)
        digest = "sha256:" + sha256_json(payload)
        self.payloads[digest] = payload
        self.ledger.append(logical_time=at, task_id=str(binding["chain"]), request_id=str(binding["id"]),
                           principal_id=str(binding["actor"]), authorization_id=str(proposal["grant"]),
                           credential_nonce=str(proposal["slot"]), origin="synthetic-origin://cursorial",
                           operation_id=str(binding["tenant"]), operation_digest=digest,
                           action=payload["verb"], resource="synthetic://cursorial/" + str(payload["resource"]),
                           arguments=payload, replay_key=str(proposal["slot"]))

    def snapshot(self) -> list[dict]:
        return [{"at": r.logical_time, "chain": int(r.task_id), "tenant": int(r.operation_id),
                 "actor": int(r.principal_id), "binding": int(r.request_id),
                 "slot": int(r.credential_nonce), "grant": int(r.authorization_id),
                 "operation": deepcopy(self.payloads[r.argument_digest])} for r in self.ledger.snapshot()]


class Host:
    def __init__(self, control: str) -> None:
        if control not in CONTROLS:
            raise ValueError("unknown synthetic control")
        self.control = control
        self.root: dict = {}
        self.epoch = 0
        self.grants: dict[int, dict] = {}
        self.delegations: dict[int, dict] = {}
        self.proposals: dict[int, dict] = {}
        self.bindings: dict[int, dict] = {}
        self.prepared: dict[int, bool] = {}
        self.spent: set[tuple[int, int]] = set()

    def observe(self, e: dict) -> None:
        kind = e["kind"]
        if kind == "chain_opened":
            self.root, self.epoch = e, e["epoch"]
        elif kind == "epoch_observed":
            self.epoch = e["epoch"]
        elif kind == "grant_state":
            self.grants[e["grant"]] = e
        elif kind == "delegation_observed":
            self.delegations[e["id"]] = e
        elif kind == "agent_proposal":
            self.proposals[e["id"]] = e
        elif kind == "request_bound":
            self.bindings[e["id"]] = e

    def _lineage(self, bind: dict, at: int) -> bool:
        actor, parent = bind["actor"], bind["delegation"]
        depth = 0
        while parent:
            depth += 1
            need(depth <= LIMITS["delegation_depth"], "delegation-depth-limit")
            link = self.delegations[parent]
            if (link["delegate"] != actor or link["tenant"] != bind["tenant"]
                    or link["epoch"] != self.epoch or at >= link["expires"]):
                return False
            actor, parent = link["issuer"], link["parent"]
        return actor == self.root["owner"] and bind["tenant"] == self.root["tenant"]

    def _current(self, bind: dict, p: dict, at: int) -> bool:
        g = self.grants.get(p["grant"])
        if g is None or g["state"] != "active" or not g["since"] <= at < g["expires"]:
            return False
        if self.control != "omit-identity" and (
            (g["grant_chain"], g["tenant"], g["grantee"]) != (bind["chain"], bind["tenant"], bind["actor"])
            or not self._lineage(bind, at)
        ):
            return False
        return (g["epoch"] == self.epoch and g["digest"] == sha256_json(p["operation"])
                and g["slot"] == p["slot"] and (self.control == "forget-slot"
                or (bind["tenant"], p["slot"]) not in self.spent))

    def decide(self, e: dict, write: Callable) -> dict:
        bind = self.bindings[e["binding"]]
        p = self.proposals[bind["proposal"]]
        permitted = self._current(bind, p, e["at"])
        if self.control == "always-allow" or (self.control == "claim-is-grant" and p["claim"] == "approved"):
            permitted = True
        elif self.control == "always-deny":
            permitted = False
        if e["phase"] == "prepare":
            self.prepared[bind["id"]] = permitted
        else:
            permitted = self.prepared[bind["id"]] and (permitted or self.control == "skip-final")
            if permitted:
                self.spent.add((bind["tenant"], p["slot"]))
            if (permitted and self.control != "fake-success") or self.control == "effect-on-deny":
                actual = dict(p["operation"])
                if self.control == "wrong-tool-effect":
                    actual["tool"] = actual["tool"] % 8 + 1
                write(e["at"], bind, p, actual)
        return {**e, "decision": "allow" if permitted else "deny", "digest": bind["digest"]}


def execute(plan: list[dict], control: str = "correct", *, mode: str = "behavior") -> dict:
    """One fresh host, one fresh ledger. The observer reads both sides of each commit."""
    need(len(plan) <= LIMITS["events"], "event-count-limit")
    host, sink = Host(control), EffectWitness()
    windows: dict[int, tuple[list, list]] = {}
    sources = {role: {"alias": "fixture-" + role + "-1", "events": []} for role in ROLES}
    for template in plan:
        e = dict(template)
        kind = e["kind"]
        role = "host"
        if kind == "gate_decision":
            before = sink.snapshot()
            e = host.decide(e, sink.apply)
            if e["phase"] == "commit":
                windows[e["id"]] = (before, sink.snapshot())
        elif kind == "effect_observed":
            role = "ledger"
            before, after = windows[e["commit"]]
            e.update(before_count=len(before), after_count=len(after), before_hash=sha256_json(before),
                     after_hash=sha256_json(after), records=after[len(before):])
        elif kind == "recovery_checkpoint":
            e["attempts"] = len(host.bindings)
        else:
            if kind == "agent_proposal":
                role = "agent"
            elif kind == "tool_definition_observed":
                role = "catalog"
            host.observe(e)
        sources[role]["events"].append(e)
    return {"schema": CHAIN, "mode": mode, "sources": sources}


def schedule(track: Tracked) -> list[dict]:
    """Recover a fixture schedule from validated observations. Strip every observed outcome."""
    plan = []
    for e in track.events:
        omitted: tuple[str, ...] = ()
        if e["kind"] == "gate_decision":
            omitted = ("decision", "digest")
        elif e["kind"] == "effect_observed":
            omitted = ("before_count", "after_count", "before_hash", "after_hash", "records")
        elif e["kind"] == "recovery_checkpoint":
            omitted = ("attempts",)
        plan.append({k: deepcopy(v) for k, v in e.items() if k not in omitted})
    return plan
