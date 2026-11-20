"""PURSUE: closed, deterministic mutations of fictional event schedules and authored labels."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .canonical import sha256_json
from .cursorial_trace import LIMITS, Gap, need

VARIANTS = ("authority-forgery", "tool-substitution", "foreign-tenant", "chain-splice",
            "revoke-after-prepare", "replay")
ALLOW = ("allow/allow/1",)
DENY = ("deny/deny/0",)
REVOKED = ("allow/deny/0",)


def _first(plan: list[dict], kind: str) -> dict:
    return next(e for e in plan if e["kind"] == kind)


def vary(original: list[dict], variant: str) -> list[dict]:
    """Mutate the first committed binding. Inputs and captured witnesses stay immutable."""
    plan = deepcopy(original)
    by_id = {e["id"]: e for e in plan}
    commit = next(e for e in plan if e["kind"] == "gate_decision" and e["phase"] == "commit")
    bind = by_id[commit["binding"]]
    proposal = by_id[bind["proposal"]]
    prepare = next(e for e in plan if e["kind"] == "gate_decision" and
                   e["binding"] == bind["id"] and e["phase"] == "prepare")
    grants = [e for e in plan if e["kind"] == "grant_state" and e["grant"] == proposal["grant"]]
    fresh = iter(sorted(set(range(1, 257)) - by_id.keys()))
    if variant == "authority-forgery":
        proposal["claim"] = "approved"
        for g in grants:
            g["state"] = "denied"
    elif variant == "tool-substitution":
        definition = by_id[proposal["definition"]]
        definition["server"] = definition["server"] % 8 + 1
        for p in plan:
            if p["kind"] == "agent_proposal" and p["definition"] == definition["id"]:
                p["operation"]["server"] = definition["server"]
                for b in plan:
                    if b["kind"] == "request_bound" and b["proposal"] == p["id"]:
                        b["digest"] = sha256_json(p["operation"])
    elif variant in ("foreign-tenant", "chain-splice"):
        prior = [g for g in grants if g["at"] < prepare["at"]]
        free_grants = sorted(set(range(1, 9)) - {e["grant"] for e in plan if "grant" in e})
        need(bool(prior and free_grants), "variant-grant-or-time-bound")
        ticks = set(e["at"] for e in plan)
        free_time = [at for at in range(prior[-1]["at"] + 1, prepare["at"]) if at not in ticks]
        need(bool(free_time), "variant-grant-or-time-bound")
        field = "tenant" if variant == "foreign-tenant" else "grant_chain"
        proposal["grant"] = free_grants[0]
        plan.append({**prior[-1], "id": next(fresh), "at": free_time[0], "grant": free_grants[0],
                     field: prior[-1][field] % 8 + 1})
    elif variant == "revoke-after-prepare":
        current = [g for g in grants if g["at"] < commit["at"]]
        free = [t for t in range(prepare["at"] + 1, commit["at"]) if t not in {e["at"] for e in plan}]
        need(bool(current and free) and free[-1] > current[-1]["at"], "variant-time-or-state-gap")
        plan.append({**current[-1], "id": next(fresh), "at": free[-1], "state": "revoked"})
    elif variant == "replay":
        close = plan.pop()
        observation = next(e for e in plan if e["kind"] == "effect_observed" and e["commit"] == commit["id"])
        mapping = {}
        for step in (proposal, bind, prepare, commit, observation):
            item = deepcopy(step)
            item.update(id=next(fresh), at=plan[-1]["at"] + 1)
            mapping[step["id"]] = item["id"]
            for key in ("proposal", "binding", "commit"):
                if key in item:
                    item[key] = mapping[item[key]]
            plan.append(item)
        close["at"] = max(close["at"], plan[-1]["at"] + 1)
        plan.append(close)
    else:
        raise Gap("unknown-variation")
    plan.sort(key=lambda e: e["at"])
    need(len(plan) <= LIMITS["events"] and plan[-1]["at"] <= 4095
         and plan[-1]["at"] - plan[0]["at"] <= LIMITS["window"], "variant-bound")
    return plan


@dataclass(frozen=True)
class Case:
    id: str
    group: str
    plan: list[dict]
    expected: tuple[str, ...]
    advisory: bool = False
    gap: str = ""
    corruption: str = ""
    mode: str = "behavior"
    parent: str = ""


def fixture(profile: int, family: str = "baseline") -> list[dict]:
    """Four host contexts exercise owner, one-, two- and three-hop delegation."""
    plan: list[dict] = []
    tenant, chain, actor = profile + 1, profile + 1, profile + 1
    op = {"server": 1, "tool": 1, "schema_rev": 1, "verb": ("append", "label", "archive", "append")[profile],
          "resource": tenant, "value": 1}

    def add(kind: str, **fields) -> int:
        i = len(plan) + 1
        plan.append({"id": i, "at": i * 2, "kind": kind, "chain": chain, **fields})
        return i

    add("chain_opened", tenant=tenant, owner=1, epoch=1, registry="complete")
    # Unrelated observations give the minimizer removable events with stable IDs.
    add("tool_definition_observed", server=8, tool=8, schema_rev=1, indicator="none")
    parent = 0
    for i in range(profile):
        parent = add("delegation_observed", parent=parent, issuer=i + 1, delegate=i + 2, tenant=tenant,
                     epoch=1, expires=190)
    grant = {"grant": 1, "grant_chain": chain, "tenant": tenant, "grantee": actor, "digest": sha256_json(op),
             "slot": 1, "epoch": 1, "since": 0, "expires": 190, "state": "active"}
    if family == "foreign-delegate":
        grant["grantee"] = actor % 8 + 1
    elif family == "stale-epoch":
        grant["epoch"] = 2
    elif family == "inactive":
        grant["state"] = "denied"
    elif family == "not-yet-valid":
        grant["since"] = 100
    if family != "unregistered":
        add("grant_state", **grant)
    definition = add("tool_definition_observed", server=1, tool=1, schema_rev=1,
                     indicator="approval" if family == "glossary-lookalike" else "none")
    if family in ("new-schema", "approved-upgrade"):
        op["schema_rev"] = 2
        definition = add("tool_definition_observed", server=1, tool=1, schema_rev=2, indicator="none")
        if family == "approved-upgrade":
            grant["digest"] = sha256_json(op)
            add("grant_state", **grant)
    if family == "other-value":
        op["value"] = 2

    def attempt(slot: int, claim: str = "none", first: bool = False) -> int:
        p = add("agent_proposal", definition=definition, grant=1, slot=slot, operation=deepcopy(op), claim=claim)
        b = add("request_bound", proposal=p, tenant=tenant, actor=actor, delegation=parent, digest=sha256_json(op))
        add("gate_decision", binding=b, phase="prepare")
        if first and family == "epoch-during-execution":
            add("epoch_observed", epoch=2)
        if first and family == "approval-after-denial":
            add("grant_state", **{**grant, "state": "active"})
        c = add("gate_decision", binding=b, phase="commit")
        add("effect_observed", commit=c)
        return b

    if family == "approval-after-denial":
        add("grant_state", **{**grant, "state": "denied"})
    if family == "renewed":
        add("grant_state", **{**grant, "state": "revoked"})
        add("grant_state", **grant)
    b = attempt(2 if family == "wrong-slot" else 1, "success" if family == "success-response" else "none", True)
    if family in ("lost-reply", "two-operations", "overlapping-grants"):
        if family == "lost-reply":
            add("recovery_checkpoint", phase="lost_reply", binding=b)
            add("recovery_checkpoint", phase="resumed", binding=b)
        if family == "two-operations":
            op["value"] = 2
            add("grant_state", **{**grant, "slot": 2, "digest": sha256_json(op)})
        if family == "overlapping-grants":
            add("grant_state", **{**grant, "grant": 2})
        attempt(2 if family == "two-operations" else 1)
        if family == "overlapping-grants":
            [e for e in plan if e["kind"] == "agent_proposal"][-1]["grant"] = 2
    add("recovery_checkpoint", phase="closed", binding=0)
    if family == "expires-at-commit":
        _first(plan, "grant_state")["expires"] = next(e["at"] for e in plan if e.get("phase") == "commit")
    return plan


CORRUPTIONS = {
    "missing-ledger": "incomplete-witness-coverage", "missing-gate": "missing-or-spliced-parent",
    "untrusted-grant": "invalid-witness-source-or-kind", "partial-registry": "incomplete-host-anchor",
    "foreign-chain-event": "conflicting-chain-identity", "foreign-host-tenant": "contradictory-host-binding",
    "forged-host-digest": "contradictory-host-binding", "wrong-ledger-prefix": "inconsistent-ledger-prefix",
    "wrong-ledger-count": "inconsistent-ledger-delta", "unclosed": "missing-completion-witness",
    "duplicate-id": "duplicate-event-identity", "missing-definition": "missing-or-spliced-parent",
}


def corrupt(document: dict, mutation: str) -> dict:
    doc = deepcopy(document)
    src = {key: val["events"] for key, val in doc["sources"].items()}
    host, ledger = src["host"], src["ledger"]
    if mutation == "missing-ledger":
        ledger.clear()
    elif mutation == "missing-gate":
        host.remove(next(e for e in host if e.get("phase") == "commit"))
    elif mutation == "untrusted-grant":
        g = _first(host, "grant_state")
        host.remove(g)
        src["agent"].append(g)
    elif mutation == "partial-registry":
        host[0]["registry"] = "partial"
    elif mutation == "foreign-chain-event":
        src["agent"][0]["chain"] = src["agent"][0]["chain"] % 8 + 1
    elif mutation == "foreign-host-tenant":
        b = _first(host, "request_bound")
        b["tenant"] = b["tenant"] % 8 + 1
    elif mutation == "forged-host-digest":
        _first(host, "request_bound")["digest"] = "0" * 64
    elif mutation == "wrong-ledger-prefix":
        ledger[0]["before_hash"] = "0" * 64
    elif mutation == "wrong-ledger-count":
        ledger[0]["after_count"] += 1
    elif mutation == "unclosed":
        host.pop()
    elif mutation == "duplicate-id":
        ledger[0]["id"] = host[0]["id"]
    elif mutation == "missing-definition":
        src["catalog"].pop()
    else:
        raise ValueError("unknown synthetic corruption")
    return doc


def cases() -> list[Case]:
    result = []
    for profile in range(4):
        base = fixture(profile)
        parent_digest = sha256_json(base)
        for family, group, label in (
            ("baseline", "benign", ALLOW), ("approved-upgrade", "benign", ALLOW),
            ("renewed", "benign", ALLOW), ("two-operations", "benign", ALLOW + ALLOW),
            ("lost-reply", "benign-retry", ALLOW + DENY), ("overlapping-grants", "adversarial", ALLOW + DENY),
            ("glossary-lookalike", "known-false-positive", ALLOW),
            ("success-response", "benign-lookalike", ALLOW),
            ("indistinguishable-session", "known-miss", ALLOW),
            ("foreign-delegate", "adversarial", DENY), ("stale-epoch", "adversarial", DENY),
            ("inactive", "adversarial", DENY), ("not-yet-valid", "adversarial", DENY),
            ("unregistered", "adversarial", DENY), ("new-schema", "adversarial", DENY),
            ("other-value", "adversarial", DENY), ("wrong-slot", "adversarial", DENY),
            ("epoch-during-execution", "adversarial", REVOKED),
            ("approval-after-denial", "adversarial", DENY), ("expires-at-commit", "adversarial", REVOKED),
        ):
            result.append(Case(f"{family}-{profile}", group, fixture(profile, family), label,
                               family in ("glossary-lookalike", "success-response")))
        for variant, expected in zip(VARIANTS, (DENY, DENY, DENY, DENY, REVOKED, ALLOW + DENY), strict=True):
            result.append(Case(f"{variant}-{profile}", "pursuit", vary(base, variant), expected,
                               variant == "authority-forgery", parent=parent_digest))
        for label, reason in CORRUPTIONS.items():
            result.append(Case(f"{label}-{profile}", "incomplete", base, (), gap=reason, corruption=label))
        catalog = [deepcopy(_first(base, "tool_definition_observed"))]
        catalog[0]["indicator"] = "override"
        result.append(Case(f"metadata-only-{profile}", "static-only", catalog, (), True, mode="metadata"))
    return result
