"""Conditional, data-only MCP review signals. All evidence strings are scanner-owned."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterator

from .agent_scan import _sha
from .canonical import sha256_json
from .mcp_input import (
    ALIAS_KEY, COUNTS, HEX, LIMITS, NUMBERS, TOOL_FIELDS, TYPES, Budget, Incomplete,
    Snapshot, alias, fields, json_value_key, parse, require, snapshot, strings,
)

# Rule descriptions, scope limitations and routine explanations travel with each signal.
RULES = {
    "WT-MCP-001": ("Instruction or secret solicitation in metadata",
                   "Phrase matching cannot establish who wrote text or how an agent treats it.",
                   "Documentation can quote a policy or describe a training exercise."),
    "WT-MCP-002": ("Definition or inventory drift",
                   "Two captures establish a declared difference. They cannot attribute its cause.",
                   "A maintainer may have upgraded, renamed or retired a capability."),
    "WT-MCP-003": ("New capability indicator",
                   "Vocabulary and hint changes describe possible access. Effective permissions are external.",
                   "An approved feature may need a new argument or an explicit behavior hint."),
    "WT-MCP-004": ("Cross-server name or display alias collision",
                   "The bounded name comparison cannot establish client routing or impersonation.",
                   "Independent servers may deliberately use the same conventional name."),
    "WT-MCP-005": ("Claim of external authority in metadata",
                   "The snapshot provides no independent evidence of the claimed approval.",
                   "Help text may describe a real approval process or quote an example."),
    "WT-MCP-006": ("Schema constraint or behavior hint changed",
                   "A local constraint change can be offset by other constraints or runtime checks.",
                   "A compatible release may accept more values or correct a schema hint."),
    "WT-MCP-007": ("Consent hint conflicts with declared operation",
                   "Both observations come from metadata. Runtime effects and user consent are unknown.",
                   "A preview tool can describe a proposed change without applying it."),
    "WT-MCP-008": ("Local stdio configuration risk indicator",
                   "Literal configuration alone cannot establish launch behavior or credential validity.",
                   "A reviewed local wrapper, test value or intentionally broad mount may be legitimate."),
}
STATUS = ("NO_PATTERN_MATCH", "REVIEW_REQUIRED", "INCONCLUSIVE")
LIMITATIONS = [
    "Static review covers the supplied captures, finite English phrases, name normalization and schema subset.",
    "The capture custodian supplies server identity, completeness, sequence and baseline provenance.",
    "Unlabelled encodings, paraphrases, visual confusables and behavior hidden in an implementation can evade inspection.",
    "Opaque digests allow correlation and guessing of low-entropy values. Publish only authorized evidence.",
    "Effective permissions, live server behavior, authorship and independent approval require external evidence.",
]

OVERRIDE = re.compile(r"\b(?:ignore|override|disregard|supersede) (?:all |the )?"
                      r"(?:(?:previous|prior|system|developer|earlier|safety) )?"
                      r"(?:instructions?|rules?|polic(?:y|ies))\b")
SOLICIT = re.compile(r"\b(?:reveal|send|provide|disclose|return|request) (?:the |your |a |all )?"
                     r"(?:api keys?|credentials?|secrets?|passwords?|access tokens?)\b")
AUTHORITY = re.compile(
    r"\b(?:(?:system|administrator|admin|developer|vendor|user) (?:has )?(?:already )?"
    r"(?:approved|authorized|granted|directive|override)|(?:approved|authorized|granted) by "
    r"(?:the )?(?:system|administrator|admin|developer|vendor|user)|"
    r"(?:system|developer) (?:message|instruction)|(?:acting|runs) as (?:an? )?"
    r"(?:administrator|admin|root)|(?:claims?|has) (?:system|administrator|admin|developer) "
    r"(?:authority|privileges|permissions))\b")
READ_ONLY = re.compile(r"\b(?:read only|non destructive|without (?:modifying|changing))\b")
OPERATION = {
    "filesystem": re.compile(r"\b(?:path|filepath|directory|filesystem|read file|write file|delete file)\b"),
    "network": re.compile(r"\b(?:url|endpoint|hostname|network|send request|upload|webhook)\b"),
    "credential": re.compile(r"\b(?:api key|password|access token|credential|secret key)\b"),
    "destructive": re.compile(r"\b(?:delete|erase|destroy|purge|overwrite)(?:s)?\b"),
    "write": re.compile(r"\b(?:write|update|create|modify|rename|upload)(?:s)?\b"),
}
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
                              "х": "x", "і": "i", "у": "y"})
ABSENT = object()


def digest(value: Any) -> str | None:
    return None if value is ABSENT else sha256_json(value)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return " ".join(re.sub(r"[\W_]+", " ", text.casefold()).split())


def words(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from words(child)
    elif isinstance(value, list):
        for child in value:
            yield from words(child)


@dataclass
class Review:
    budget: Budget = field(default_factory=Budget)
    findings: list[dict] = field(default_factory=list)
    gaps: set[tuple[str, str, str]] = field(default_factory=set)

    def emit(self, number: int, scope: str, location: str, basis: str, **observed: Any) -> None:
        self.budget.spend()
        require(len(self.findings) < LIMITS["findings"], "finding-count-limit")
        rule = f"WT-MCP-{number:03}"
        title, limitation, benign = RULES[rule]
        self.findings.append({"rule_id": rule, "title": title, "scope": scope, "field": location,
                              "basis": basis, "observed": observed, "limitation": limitation,
                              "possible_benign_explanation": benign, "classification": "REVIEW_REQUIRED"})


def _text(review: Review, scope: str, location: str, value: Any) -> None:
    matches = set()
    for text in words(value):
        review.budget.spend(1 + len(text) // 64)
        encoding = "plain or Unicode-normalized"
        if text.casefold().startswith("base64:"):
            try:
                text = base64.b64decode(text[7:], validate=True).decode("utf-8")
                encoding = "explicit base64 UTF-8"
            except (ValueError, UnicodeError, binascii.Error):
                review.gaps.add(("candidate", "unsupported-labelled-encoding", scope))
                continue
        elif re.search(r"%[a-fA-F0-9]{2}", text):
            try:
                raw = re.split(r"(%[a-fA-F0-9]{2})", text)
                text = b"".join(bytes.fromhex(t[1:]) if i % 2 else t.encode("utf-8")
                                for i, t in enumerate(raw)).decode("utf-8")
                encoding = "percent-decoded UTF-8"
            except UnicodeError:
                review.gaps.add(("candidate", "unsupported-labelled-encoding", scope))
                continue
        phrase = normalize(text)
        for rule, pattern, basis in ((1, OVERRIDE, "Instruction override phrase"),
                                     (1, SOLICIT, "Request for a secret category"),
                                     (5, AUTHORITY, "Claimed authority or prior approval")):
            if pattern.search(phrase):
                matches.add((rule, basis, encoding))
    for rule, basis, encoding in sorted(matches):
        review.emit(rule, scope, location, basis, encoding=encoding)


def _approval_fields(value: Any) -> bool:
    if isinstance(value, list):
        return any(_approval_fields(item) for item in value)
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if (normalize(key) in ("approved by", "authorized by", "granted by")
                and isinstance(item, str) and normalize(item) in
                ("system", "administrator", "admin", "developer", "vendor", "user")):
            return True
        if _approval_fields(item):
            return True
    return False


def _input_terms(schema: Any) -> Iterator[str]:
    if not isinstance(schema, dict):
        return
    for key, child in schema.get("properties", {}).items():
        yield key
        yield from _input_terms(child)
    for key in ("enum", "const", "default"):
        yield from words(schema.get(key))
    for key in ("additionalProperties", "items"):
        yield from _input_terms(schema.get(key))


def _capabilities(tool: dict) -> set[str]:
    terms = [tool.get("name", ""), tool.get("description", "")]
    terms.extend(_input_terms(tool.get("inputSchema")))
    result = set()
    for term in terms:
        normalized = normalize(term)
        result.update(name for name, pattern in OPERATION.items() if pattern.search(normalized))
    return result


def _scope_inventory(snap: Snapshot) -> dict:
    return {
        "stream_alias": alias("stream", snap.stream), "sequence": snap.sequence,
        "predecessor_field_sha256": digest(snap.previous) if snap.previous is not None else None,
        "servers": [{"id": alias("server", server), "info_sha256": digest(info)}
                    for server, info in sorted(snap.servers.items())],
        "tools": [{"id": alias("tool", server, name), "server": alias("server", server),
                   "definition_sha256": digest(tool)}
                  for (server, name), tool in sorted(snap.tools.items())],
    }


def _type_set(schema: dict) -> set:
    value = schema.get("type", list(TYPES))
    choices = {value} if isinstance(value, str) else set(value)
    if "number" in choices:
        choices.add("integer")
    return choices


def _widen(review: Review, scope: str, field_name: str, before: Any, after: Any,
           path: tuple[str, ...] = ()) -> None:
    """Compare matching schema nodes. No regex compilation, references or satisfiability solver."""
    review.budget.spend()
    if digest(before) == digest(after):
        return
    reasons = []
    if before is False or after is True:
        reasons.append("A rejecting schema was relaxed or a schema was replaced by true")
    elif isinstance(before, dict) and isinstance(after, dict):
        if _type_set(after) - _type_set(before):
            reasons.append("Additional JSON types declared")
        if set(before.get("required", [])) - set(after.get("required", [])):
            reasons.append("Previously required property omitted from required")
        if "enum" in before and ("enum" not in after or
                {json_value_key(x) for x in after["enum"]} - {json_value_key(x) for x in before["enum"]}):
            reasons.append("Enumeration removed or allowed values added")
        if "const" in before and ("const" not in after or
                                   json_value_key(before["const"]) != json_value_key(after["const"])):
            reasons.append("Constant constraint removed or replaced")
        for key in sorted((COUNTS | NUMBERS) & before.keys()):
            lower = key.startswith(("min", "exclusiveMin"))
            if (key not in after or (lower and after[key] < before[key])
                    or (not lower and after[key] > before[key])):
                reasons.append("Constraint relaxed at " + key)
        if before.get("uniqueItems") and not after.get("uniqueItems"):
            reasons.append("Array uniqueness constraint removed")
        for key in ("readOnly", "writeOnly"):
            if before.get(key, False) != after.get(key, False):
                reasons.append("Schema behavior hint changed at " + key)
        left, right = before.get("properties", {}), after.get("properties", {})
        for key in sorted(left.keys() & right.keys()):
            _widen(review, scope, field_name, left[key], right[key], (*path, "properties", key))
        # Never recursively expand a shared fallback schema against every
        # missing property. That can multiply work exponentially across levels.
        prior_fallback = digest(before.get("additionalProperties", True))
        next_fallback = digest(after.get("additionalProperties", True))
        for key in sorted(left.keys() ^ right.keys()):
            review.budget.spend()
            prior_digest = digest(left[key]) if key in left else prior_fallback
            next_digest = digest(right[key]) if key in right else next_fallback
            if prior_digest == next_digest:
                continue
            was = left.get(key, before.get("additionalProperties", True))
            now = right.get(key, after.get("additionalProperties", True))
            if was is False or (was is not True and now is True):
                review.emit(6, scope, field_name, "Property became eligible or its local restriction was removed",
                            node_alias=alias("node", *path, "properties", key),
                            before_sha256=prior_digest, after_sha256=next_digest)
            elif isinstance(was, dict) and isinstance(now, dict):
                review.gaps.add(("comparison", "unresolved-property-fallback-comparison", scope))
        for key in ("additionalProperties", "items"):
            _widen(review, scope, field_name, before.get(key, True), after.get(key, True), (*path, key))
    for basis in reasons:
        review.emit(6, scope, field_name, basis, node_alias=alias("node", *path),
                    before_sha256=digest(before), after_sha256=digest(after))
    if field_name == "inputSchema" and any("hint" not in reason for reason in reasons):
        properties = [normalize(path[i + 1]) for i in range(len(path) - 1) if path[i] == "properties"]
        for category, pattern in OPERATION.items():
            if any(pattern.search(name) for name in properties):
                review.emit(3, scope, field_name, "Constraint relaxed on an operation-related argument",
                            category=category, node_alias=alias("node", *path))


def _candidate(review: Review, snap: Snapshot) -> None:
    names: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for server, info in sorted(snap.servers.items()):
        for key in ("name", "title", "description"):
            _text(review, alias("server", server), "serverInfo." + key, info.get(key))
    for (server, name), tool in sorted(snap.tools.items()):
        scope = alias("tool", server, name)
        hints = tool.get("annotations", {})
        for key, value in sorted(tool.items()):
            if key not in TOOL_FIELDS:
                _text(review, scope, "extension", {key: value})
            elif key != "icons":
                _text(review, scope, key, value)
        if _approval_fields(tool.get("_meta")):
            review.emit(5, scope, "_meta", "Structured approval claim names an external authority role")
        labels = [name, tool.get("title", ""), hints.get("title", ""),
                  *tool.get("_meta", {}).get(ALIAS_KEY, [])]
        for label_text in labels:
            key = normalize(label_text).translate(CONFUSABLES).replace(" ", "")
            if key:
                names[key][server].add(scope)
        caps = _capabilities(tool)
        prose = normalize(tool.get("description", ""))
        if ("destructive" in caps and hints.get("destructiveHint") is False):
            review.emit(7, scope, "annotations", "Non-destructive hint with destructive operation vocabulary")
        if caps & {"write", "destructive"} and (hints.get("readOnlyHint") is True or READ_ONLY.search(prose)):
            review.emit(7, scope, "tool", "Read-only claim with a write or destructive operation indicator")
        if hints.get("readOnlyHint") is True and hints.get("destructiveHint") is True:
            review.emit(7, scope, "annotations", "Read-only and destructive hints are both explicitly true")
    for key, group in sorted(names.items()):
        if len(group) > 1:
            review.emit(4, alias("label", key), "display-names", "Normalized label shared across server identities",
                        tools=sorted(t for members in group.values() for t in members),
                        servers=sorted(alias("server", s) for s in group))


def _compare(review: Review, old: Snapshot, new: Snapshot) -> None:
    for server in sorted(old.servers.keys() | new.servers.keys()):
        prior = old.servers.get(server, ABSENT)
        current = new.servers.get(server, ABSENT)
        scope = alias("server", server)
        if prior is ABSENT or current is ABSENT:
            review.emit(2, scope, "servers", "Server identity added" if prior is ABSENT else "Server identity removed",
                        before_sha256=digest(prior), after_sha256=digest(current))
        else:
            for key in sorted((prior.keys() | current.keys()) - {"version"}):
                if digest(prior.get(key, ABSENT)) != digest(current.get(key, ABSENT)):
                    review.emit(2, scope, "serverInfo." + key, "Server identity metadata changed",
                                before_sha256=digest(prior.get(key, ABSENT)),
                                after_sha256=digest(current.get(key, ABSENT)))
    for identity in sorted(old.tools.keys() | new.tools.keys()):
        scope = alias("tool", *identity)
        prior = old.tools.get(identity)
        current = new.tools.get(identity)
        if prior is None or current is None:
            review.emit(2, scope, "tools", "Tool added" if prior is None else "Tool removed",
                        before_sha256=digest(prior) if prior is not None else None,
                        after_sha256=digest(current) if current is not None else None)
        else:
            for key in sorted(prior.keys() | current.keys()):
                left, right = prior.get(key, ABSENT), current.get(key, ABSENT)
                if digest(left) == digest(right):
                    continue
                review.emit(2, scope, key if key in TOOL_FIELDS else "extension", "Tool field changed",
                            before_sha256=digest(left), after_sha256=digest(right))
                if key in ("inputSchema", "outputSchema"):
                    if right is ABSENT:
                        review.emit(6, scope, key, "Declared output contract removed", before_sha256=digest(left))
                    elif left is not ABSENT:
                        _widen(review, scope, key, left, right)
        if current is not None:
            for category in sorted(_capabilities(current) - _capabilities(prior or {})):
                review.emit(3, scope, "tool", "New operation vocabulary", category=category)
            old_hints = (prior or {}).get("annotations", {})
            new_hints = current.get("annotations", {})
            for key, restrictive, default in (("readOnlyHint", True, False),
                                              ("destructiveHint", False, True),
                                              ("openWorldHint", False, True)):
                if (old_hints.get(key, default) is restrictive and
                        new_hints.get(key, default) is not restrictive):
                    review.emit(3, scope, "annotations", "Restrictive hint relaxed or withdrawn", hint=key)


def _config(review: Review, raw: bytes, candidate: Snapshot) -> None:
    doc = parse(raw, LIMITS["config_bytes"], review.budget)
    fields(doc, {"mcpServers"}, {"mcpServers"}, "unsupported-config-format")
    servers = doc["mcpServers"]
    require(isinstance(servers, dict) and len(servers) <= LIMITS["servers"], "unsupported-config-servers")
    for server, entry in sorted(servers.items()):
        require(server in candidate.servers, "unmapped-config-server")
        scope = alias("server", server)
        fields(entry, {"command"}, {"command", "args", "env"}, "unsupported-stdio-config")
        command, args, env = entry["command"], entry.get("args", []), entry.get("env", {})
        require(isinstance(command, str) and bool(command.strip()) and strings(args)
                and isinstance(env, dict) and all(isinstance(v, str) for v in env.values()),
                "malformed-stdio-config")
        program = re.split(r"[/\\]", command.casefold())[-1].removesuffix(".exe")
        switches = {"sh": "-c", "bash": "-c", "zsh": "-c", "cmd": "/c", "pwsh": "-command",
                    "powershell": "-command", "python": "-c", "python3": "-c", "node": "-e"}
        inline = program in switches and switches[program] in [a.casefold() for a in args]
        shell_flags = program in ("sh", "bash", "zsh") and any(
            a.startswith("-") and "c" in a and a.isascii() and a[1:].isalpha() for a in args)
        if inline or shell_flags:
            review.emit(8, scope, "config.args", "Interpreter with an inline command switch")
        if any(a == "/" or re.fullmatch(r"[A-Za-z]:[/\\]", a) for a in args):
            review.emit(8, scope, "config.args", "Argument names an entire filesystem root")
        for key, value in env.items():
            if (re.search(r"PASSWORD|SECRET|TOKEN|API[_-]?KEY", key, re.I) and value and
                    not re.fullmatch(r"\$\{[A-Za-z_][A-Za-z_0-9]*\}", value)):
                review.emit(8, scope, "config.env", "Literal value under a credential-shaped environment key")
                break


def inspect(baseline: bytes | None, candidate: bytes | None, config: bytes | None = None, *,
            baseline_sha256: str | None = None, config_selected: bool = False) -> dict:
    review = Review()
    sources = {}
    parsed: dict[str, Snapshot] = {}
    for role, raw in (("baseline", baseline), ("candidate", candidate)):
        sources[role] = {"sha256": _sha(raw) if raw is not None else None,
                         "bytes": len(raw) if raw is not None else None}
        try:
            require(raw is not None, "unavailable-or-unsafe-input")
            snap = snapshot(raw, review.budget)
            parsed[role] = snap
            sources[role].update(_scope_inventory(snap))
            review.gaps.update((role, code, scope) for code, scope in snap.gaps)
        except Incomplete as error:
            review.gaps.add((role, str(error), role))
    old, new = parsed.get("baseline"), parsed.get("candidate")
    if baseline_sha256 is not None and (not HEX.fullmatch(baseline_sha256)
                                        or baseline_sha256 != sources["baseline"]["sha256"]):
        review.gaps.add(("baseline", "baseline-pin-mismatch", "baseline"))
        old = None
    if config_selected or config is not None:
        sources["config"] = {"sha256": _sha(config) if config is not None else None,
                             "bytes": len(config) if config is not None else None}
        try:
            require(config is not None and new is not None, "config-or-candidate-unavailable")
            _config(review, config, new)
        except Incomplete as error:
            review.gaps.add(("config", str(error), "config"))
    try:
        if new is not None:
            _candidate(review, new)
        if old is not None and new is not None:
            require(old.stream == new.stream, "capture-stream-mismatch")
            require(new.sequence >= old.sequence, "capture-rollback")
            if old.sequence == new.sequence:
                require(baseline == candidate, "capture-sequence-reused")
            elif new.previous is not None:
                require(new.previous == sources["baseline"]["sha256"], "stale-baseline-predecessor")
            _compare(review, old, new)
    except Incomplete as error:
        review.gaps.add(("comparison", str(error), "snapshot-pair"))
    code = 2 if review.gaps else int(bool(review.findings))
    return {
        "status": STATUS[code], "exit_code": code, "sources": sources, "findings": review.findings,
        "coverage_gaps": [{"role": r, "reason": c, "scope": s} for r, c, s in sorted(review.gaps)],
        "work_units": review.budget.used,
    }
