"""Independent expected-state oracle over an already correlated fictional history.

No gate, fixture builder, ledger, digest helper or detector imports. Read only
host facts and proposed operation bytes when constructing expected outcomes.
"""

import hashlib
import json


def reference(events: list[dict]) -> list[dict]:
    anchor = events[0]
    rows = {}
    consumed = set()
    for position, gate in enumerate(events):
        if gate["kind"] != "gate_decision":
            continue
        history = events[:position]
        by_id = {fact["id"]: fact for fact in history}
        bind = by_id[gate["binding"]]
        proposal = by_id[bind["proposal"]]
        operation = proposal["operation"]
        message = json.dumps(operation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        fingerprint = hashlib.sha256(message).hexdigest()
        epoch = next((x["epoch"] for x in reversed(history) if x["kind"] == "epoch_observed"), anchor["epoch"])
        # Forward reachability through attested delegation edges at this time.
        reachable = {0: anchor["owner"]}
        for fact in history:
            if (fact["kind"] == "delegation_observed" and reachable.get(fact["parent"]) == fact["issuer"]
                    and fact["tenant"] == anchor["tenant"] and fact["epoch"] == epoch
                    and fact["expires"] > gate["at"]):
                reachable[fact["id"]] = fact["delegate"]
        grants = [x for x in history if x["kind"] == "grant_state" and x["grant"] == proposal["grant"]]
        g = grants[-1] if grants else None
        expected_scope = (anchor["chain"], anchor["tenant"], bind["actor"], epoch, proposal["slot"], fingerprint)
        slot = (anchor["tenant"], proposal["slot"])
        allowed = bool(g and (g["grant_chain"], g["tenant"], g["grantee"], g["epoch"], g["slot"], g["digest"])
                       == expected_scope and g["state"] == "active" and g["since"] <= gate["at"] < g["expires"]
                       and reachable.get(bind["delegation"]) == bind["actor"] and slot not in consumed)
        row = rows.setdefault(bind["id"], {"binding": bind["id"], "digest": fingerprint, "records": []})
        if gate["phase"] == "commit":
            allowed = allowed and row["prepare"] == "allow"
            if allowed:
                consumed.add(slot)
                row["records"].append({"binding": bind["id"], "at": gate["at"], "chain": anchor["chain"],
                                       "tenant": anchor["tenant"], "actor": bind["actor"], "slot": proposal["slot"],
                                       "grant": proposal["grant"], "operation": operation.copy()})
        row[gate["phase"]] = "allow" if allowed else "deny"
    return list(rows.values())
