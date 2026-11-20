"""SCENT and TRACK for finite fictional witness streams. No collection or execution."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .agent_scan import _open_directory, _read_file
from .canonical import sha256_json

CHAIN = "wolftrap.cursorial-chain/v1"
GRAPH = "wolftrap.cursorial-graph/v1"
ROLES = ("catalog", "agent", "host", "ledger")
LIMITS = {"bytes": 98304, "json_depth": 12, "json_nodes": 4096, "events": 48,
          "edges": 384, "graph_depth": 32, "delegation_depth": 4, "window": 128,
          "minimization_evaluations": 64, "fresh_replays": 2}


class Gap(ValueError):
    """A fixed, publishable reason for insufficient or contradictory evidence."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Gap(reason)


def _pairs(pairs: list) -> dict:
    obj = dict(pairs)
    need(len(obj) == len(pairs), "duplicate-json-key")
    return obj


def _integer(token: str) -> int:
    need(len(token) <= 6, "unsupported-number")
    return int(token)


def _reject_number(_: str) -> None:
    raise Gap("unsupported-number")


def decode(raw: bytes) -> dict:
    need(0 < len(raw) <= LIMITS["bytes"], "input-byte-limit")
    try:
        text = raw.decode("utf-8")
        quoted = escaped = False
        depth = separators = 0
        for c in text:
            if quoted:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    quoted = False
            elif c == '"':
                quoted = True
            elif c in "[{":
                depth += 1
                need(depth <= LIMITS["json_depth"], "json-depth-limit")
            elif c in "]}":
                depth -= 1
                need(depth >= 0, "malformed-json")
            elif c in ":,":
                separators += 1
                need(separators <= LIMITS["json_nodes"], "json-complexity-limit")
        obj = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                         parse_float=_reject_number, parse_constant=_reject_number)
    except Gap:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise Gap("malformed-json") from None
    stack, nodes = [obj], 0
    while stack:
        item = stack.pop()
        nodes += 1
        if isinstance(item, dict):
            nodes += len(item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        need(nodes <= LIMITS["json_nodes"], "json-complexity-limit")
    validate(obj, "chain")
    return obj


@lru_cache(maxsize=2)
def _schema(which: str) -> dict:
    need(which in ("chain", "graph"), "unsupported-schema")
    fd = _open_directory(Path(__file__).parent / "schemas")
    try:
        return json.loads(_read_file(fd, "cursorial-" + which + "-v1.schema.json", 65536))
    finally:
        os.close(fd)


def validate(document: Any, which: str) -> None:
    """Validate against the shipped closed schemas. Only local, trusted schema refs are used."""
    schema = _schema(which)
    definitions = schema["$defs"]

    def visit(value: Any, spec: dict) -> None:
        if "$ref" in spec:
            spec = definitions[spec["$ref"].split("/")[-1]]
        if "oneOf" in spec:
            # Alternatives are disjoint on the mandatory kind constant.
            need(isinstance(value, dict) and isinstance(value.get("kind"), str), "invalid-event-shape")
            permitted = {entry["$ref"].split("/")[-1] for entry in spec["oneOf"]}
            need(value["kind"] in permitted, "invalid-witness-source-or-kind")
            spec = definitions[value["kind"]]
        if "const" in spec:
            need(value == spec["const"], "invalid-schema-or-source-alias")
        elif "enum" in spec:
            need(value in spec["enum"], "unsupported-enumeration")
        elif spec["type"] == "object":
            need(isinstance(value, dict) and value.keys() == spec["properties"].keys(),
                 "invalid-object-fields")
            for key, child in spec["properties"].items():
                visit(value[key], child)
        elif spec["type"] == "array":
            need(isinstance(value, list) and spec["minItems"] <= len(value) <= spec["maxItems"],
                 "array-shape-or-bound")
            for item in value:
                visit(item, spec["items"])
        elif spec["type"] == "integer":
            need(type(value) is int and spec["minimum"] <= value <= spec["maximum"], "integer-shape-or-bound")
        else:
            need(isinstance(value, str) and spec["minLength"] <= len(value) <= spec["maxLength"]
                 and re.fullmatch(spec["pattern"], value) is not None, "invalid-digest")

    visit(document, schema)


@dataclass
class Tracked:
    events: list[dict]
    graph: dict
    advisories: list[dict]


def scent(doc: dict) -> list[dict]:
    validate(doc, "chain")
    need(sum(len(s["events"]) for s in doc["sources"].values()) <= LIMITS["events"], "event-count-limit")
    found = []
    for role, field in (("catalog", "indicator"), ("agent", "claim")):
        stream = doc["sources"][role]
        for event in stream["events"]:
            if event[field] != "none":
                found.append({"event": event["id"], "source": stream["alias"], "basis": role + "-" + event[field],
                              "classification": "STATIC REVIEW SIGNAL"})
    return found


def track(doc: dict) -> Tracked:
    advisories = scent(doc)
    timeline = []
    for role in ROLES:
        events = doc["sources"][role]["events"]
        need(all(a["at"] < b["at"] for a, b in zip(events, events[1:])), "unordered-source")
        timeline.extend((event, role) for event in events)
    need(0 < len(timeline) <= LIMITS["events"], "event-count-limit")
    timeline.sort(key=lambda pair: pair[0]["at"])
    events = [e for e, _ in timeline]
    need(len({e["id"] for e in events}) == len(events), "duplicate-event-identity")
    need(len({e["at"] for e in events}) == len(events), "ambiguous-logical-order")
    need(events[-1]["at"] - events[0]["at"] <= LIMITS["window"], "logical-window-limit")
    root = events[0]
    need(all(e["chain"] == root["chain"] for e in events), "conflicting-chain-identity")
    nodes = [{"id": e["id"], "at": e["at"], "kind": e["kind"], "chain": e["chain"],
              "source": doc["sources"][role]["alias"]} for e, role in timeline]
    edges: list[dict] = []
    graph = {"schema": GRAPH, "nodes": nodes, "edges": edges}
    if doc["mode"] == "metadata":
        need(all(role == "catalog" for _, role in timeline), "metadata-profile-conflict")
        return Tracked(events, graph, advisories)

    need(root["kind"] == "chain_opened" and root["registry"] == "complete", "incomplete-host-anchor")
    seen = {root["id"]: root}
    depth = {root["id"]: 0}
    grants, delegates, bindings, phases, windows, slots = {}, {}, {}, {}, {}, {}
    proposals, bound_proposals = set(), set()
    epoch, epoch_event = root["epoch"], root["id"]
    ledger: list[dict] = []
    last_window = recovery = lost = pending_commit = 0
    closed = False
    for e in events[1:]:
        node, kind = e["id"], e["kind"]
        depth[node] = 0

        def edge(parent: int, relation: str, required_kind: str | None = None) -> dict:
            need(parent in seen and (required_kind is None or seen[parent]["kind"] == required_kind),
                 "missing-or-spliced-parent")
            edges.append({"from": parent, "to": node, "relation": relation})
            depth[node] = max(depth[node], depth[parent] + 1)
            need(depth[node] <= LIMITS["graph_depth"] and len(edges) <= LIMITS["edges"], "graph-bound")
            return seen[parent]

        need(not closed, "events-after-closure")
        if kind == "tool_definition_observed":
            edge(root["id"], "chain")
        elif kind == "grant_state":
            edge(grants.get(e["grant"], root["id"]), "grant")
            need(e["since"] < e["expires"], "contradictory-grant-interval")
            grants[e["grant"]] = node
        elif kind == "epoch_observed":
            edge(epoch_event, "epoch")
            need(e["epoch"] > epoch, "epoch-rollback")
            epoch, epoch_event = e["epoch"], node
        elif kind == "delegation_observed":
            parent = edge(e["parent"] or root["id"], "delegation",
                          "delegation_observed" if e["parent"] else "chain_opened")
            lineage = delegates.get(parent["id"], (root["owner"],))
            need(e["tenant"] == root["tenant"] and e["issuer"] == lineage[-1]
                 and e["delegate"] not in lineage, "contradictory-delegation-lineage")
            need(len(lineage) <= LIMITS["delegation_depth"], "delegation-depth-limit")
            delegates[node] = (*lineage, e["delegate"])
        elif kind == "agent_proposal":
            definition = edge(e["definition"], "definition", "tool_definition_observed")
            need(all(definition[k] == e["operation"][k] for k in ("server", "tool", "schema_rev")),
                 "unresolved-tool-identity")
            proposals.add(node)
        elif kind == "request_bound":
            proposal = edge(e["proposal"], "proposal", "agent_proposal")
            edge(root["id"], "chain")
            need(e["proposal"] not in bound_proposals and e["tenant"] == root["tenant"]
                 and e["digest"] == sha256_json(proposal["operation"]), "contradictory-host-binding")
            if e["delegation"]:
                edge(e["delegation"], "delegation", "delegation_observed")
            need(not lost, "retry-without-recovery")
            if recovery:
                edge(recovery, "recovery")
            bound_proposals.add(e["proposal"])
            bindings[node] = proposal
        elif kind == "gate_decision":
            binding = edge(e["binding"], "binding", "request_bound")
            proposal = bindings[binding["id"]]
            key = (binding["id"], e["phase"])
            need(key not in phases and e["digest"] == binding["digest"], "contradictory-decision-witness")
            edge(grants.get(proposal["grant"], root["id"]), "grant")
            edge(epoch_event, "epoch")
            if proposal["slot"] in slots:
                edge(slots[proposal["slot"]], "previous-slot")
            if e["phase"] == "commit":
                need(not pending_commit, "overlapping-ledger-windows")
                edge(phases.get((binding["id"], "prepare"), 0), "prepare", "gate_decision")
                slots[proposal["slot"]] = pending_commit = node
            phases[key] = node
        elif kind == "effect_observed":
            commit = edge(e["commit"], "commit", "gate_decision")
            need(e["commit"] == pending_commit and commit["phase"] == "commit", "spliced-ledger-window")
            if last_window:
                edge(last_window, "ledger-prefix")
            need((e["before_count"], e["before_hash"]) == (len(ledger), sha256_json(ledger)),
                 "inconsistent-ledger-prefix")
            ledger.extend(e["records"])
            need((e["after_count"], e["after_hash"]) == (len(ledger), sha256_json(ledger)),
                 "inconsistent-ledger-delta")
            windows[commit["binding"]] = last_window = node
            pending_commit = 0
        elif kind == "recovery_checkpoint":
            need(e["attempts"] == len(bindings), "checkpoint-attempt-count")
            if e["phase"] == "closed":
                need(not e["binding"] and not lost and not pending_commit and bindings
                     and proposals == bound_proposals and bindings.keys() == windows.keys(),
                     "incomplete-witness-coverage")
                for window in windows.values():
                    edge(window, "completion")
                if recovery:
                    edge(recovery, "completion")
                closed = True
            else:
                edge(windows.get(e["binding"], 0), "recovery", "effect_observed")
                if e["phase"] == "lost_reply":
                    need(not lost, "contradictory-recovery")
                    lost = e["binding"]
                else:
                    need(lost == e["binding"], "contradictory-recovery")
                    edge(recovery, "recovery", "recovery_checkpoint")
                    lost = 0
                recovery = node
        else:
            raise Gap("duplicate-host-anchor")
        seen[node] = e
    need(closed, "missing-completion-witness")
    return Tracked(events, graph, advisories)
