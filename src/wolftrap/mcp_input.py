"""Strict, finite input profile for saved MCP 2025-11-25 tools/list results."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .canonical import sha256_json

VERSION = "2025-11-25"
SNAPSHOT = "wolftrap.mcp-tools-snapshot/v1"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ALIAS_KEY = "org.wolftrap/aliases"
LIMITS = {
    "snapshot_bytes": 262144, "config_bytes": 65536, "json_depth": 32,
    "json_nodes_per_file": 8192, "string_characters": 8192, "servers": 32,
    "tools_per_snapshot": 128, "pages_per_snapshot": 64, "aliases_per_tool": 16,
    "total_work_units": 65536, "findings": 256, "path_components": 64,
}
TOOL_FIELDS = {"name", "title", "description", "inputSchema", "outputSchema",
               "annotations", "execution", "icons", "_meta"}
HINTS = {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
VISIBLE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
TYPES = {"null", "boolean", "integer", "number", "string", "object", "array"}
COUNTS = {"minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"}
NUMBERS = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"}


class Incomplete(ValueError):
    """Only fixed public reason codes may be passed to this exception."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Incomplete(reason)


@dataclass
class Budget:
    used: int = 0

    def spend(self, units: int = 1) -> None:
        self.used += units
        require(self.used <= LIMITS["total_work_units"], "inspection-work-limit")


def _pairs(items: list) -> dict:
    result = {}
    for key, value in items:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def _number(text: str) -> int | float:
    # Reject truncation, underflow and adjacent integers merged by binary64 clients.
    require(len(text) <= 64, "unsupported-number")
    approximate = float(text)
    require(math.isfinite(approximate) and abs(approximate) <= 2**53 - 1, "unsupported-number")
    require(Decimal(text) == Decimal(str(approximate)), "unsupported-number")
    return float(text) if any(c in text for c in ".eE") else int(text)


def parse(raw: bytes, byte_limit: int, budget: Budget) -> Any:
    require(0 < len(raw) <= byte_limit, "file-byte-limit")
    budget.spend(1 + len(raw) // 32)
    try:
        text = raw.decode("utf-8", errors="strict")
        # Bound parser recursion and allocation before constructing a Python tree.
        quoted = escaped = False
        depth = tokens = 0
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                require(depth <= LIMITS["json_depth"], "json-depth-limit")
                tokens += 1
            elif char in "]}":
                depth -= 1
                require(depth >= 0, "malformed-json")
            elif char in ",:":
                tokens += 1
            require(tokens <= 2 * LIMITS["json_nodes_per_file"], "json-node-limit")
        document = json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                              parse_float=_number, parse_constant=_number)
    except Incomplete:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Incomplete("malformed-json") from None
    pending = [document]
    nodes = 0
    while pending:
        item = pending.pop()
        nodes += 1
        require(nodes <= LIMITS["json_nodes_per_file"], "json-node-limit")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            require(len(item) <= LIMITS["string_characters"], "string-length-limit")
            require(not re.search(r"[\ud800-\udfff]", item), "invalid-unicode-scalar")
    budget.spend(nodes)
    return document


def fields(value: Any, required: set, allowed: set, reason: str) -> None:
    require(isinstance(value, dict) and required <= value.keys() <= allowed, reason)


def label(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) <= 256 and len(value) <= 256


def strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


@dataclass
class Snapshot:
    stream: str
    sequence: int
    previous: str | None
    servers: dict[str, dict] = field(default_factory=dict)
    tools: dict[tuple[str, str], dict] = field(default_factory=dict)
    gaps: set[tuple[str, str]] = field(default_factory=set)


def alias(kind: str, *parts: str) -> str:
    return kind + "-" + sha256_json([kind, *parts])


def _icons(value: Any) -> None:
    require(isinstance(value, list), "malformed-icons")
    for icon in value:
        fields(icon, {"src"}, {"src", "mimeType", "sizes", "theme"}, "unsupported-icon")
        require(isinstance(icon["src"], str) and bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:\S+", icon["src"])) and
                isinstance(icon.get("mimeType", ""), str) and strings(icon.get("sizes", [])) and
                icon.get("theme", "light") in ("light", "dark"), "malformed-icons")


def _schema(value: Any, gaps: set, scope: str, *, root: bool = True) -> None:
    if not root and isinstance(value, bool):
        return
    require(isinstance(value, dict), "malformed-schema")
    if root:
        require(value.get("type") == "object", "unsupported-schema-root")
    for key, item in value.items():
        if key == "$schema":
            if item != DIALECT:
                gaps.add(("unsupported-schema-dialect", scope))
        elif key == "type":
            choices = item if isinstance(item, list) else [item]
            require(strings(choices) and bool(choices) and len(set(choices)) == len(choices)
                    and set(choices) <= TYPES, "malformed-schema-type")
        elif key == "properties":
            require(isinstance(item, dict), "malformed-properties")
            for child in item.values():
                if root:
                    require(isinstance(child, dict), "unsupported-mcp-property-schema")
                _schema(child, gaps, scope, root=False)
        elif key in ("additionalProperties", "items"):
            _schema(item, gaps, scope, root=False)
        elif key == "required":
            require(strings(item) and len(set(item)) == len(item), "malformed-required")
        elif key == "enum":
            require(isinstance(item, list) and bool(item), "unsupported-enum")
            # JSON Schema regards numerically equal integers and reals as equal.
            fingerprints = {json_value_key(v) for v in item}
            require(len(fingerprints) == len(item), "ambiguous-enum")
        elif key in COUNTS:
            require(type(item) is int and item >= 0, "malformed-schema-bound")
        elif key in NUMBERS:
            require(type(item) in (float, int), "malformed-schema-bound")
        elif key in ("title", "description"):
            require(isinstance(item, str), "malformed-schema-text")
        elif key in ("readOnly", "writeOnly", "deprecated", "uniqueItems"):
            require(type(item) is bool, "malformed-schema-hint")
        elif key == "examples":
            require(isinstance(item, list), "malformed-schema-examples")
        elif key not in ("const", "default"):
            gaps.add(("unsupported-schema-keyword", scope))


def json_value_key(value: Any) -> str:
    """Canonical equality for JSON values, keeping booleans distinct from numbers."""
    if type(value) is float and value.is_integer():
        value = int(value)
    elif isinstance(value, dict):
        return sha256_json(["object", {k: json_value_key(v) for k, v in value.items()}])
    elif isinstance(value, list):
        return sha256_json(["array", [json_value_key(v) for v in value]])
    return sha256_json(["scalar", value])


def _tool(tool: Any, server: str, snap: Snapshot) -> None:
    require(isinstance(tool, dict) and label(tool.get("name")) and "inputSchema" in tool,
            "malformed-tool")
    name = tool["name"]
    scope = alias("tool", server, name)
    require((server, name) not in snap.tools, "duplicate-tool-identity")
    require(len(snap.tools) < LIMITS["tools_per_snapshot"], "tool-count-limit")
    snap.tools[server, name] = tool
    if tool.keys() - TOOL_FIELDS:
        snap.gaps.add(("unsupported-tool-field", scope))
    if not VISIBLE.fullmatch(name):
        snap.gaps.add(("nonportable-tool-name", scope))
    require(all(isinstance(tool.get(k, ""), str) for k in ("description", "title")),
            "malformed-tool-text")
    annotations = tool.get("annotations", {})
    require(isinstance(annotations, dict) and isinstance(annotations.get("title", ""), str)
            and all(type(annotations[k]) is bool for k in HINTS & annotations.keys()),
            "malformed-annotations")
    if annotations.keys() - HINTS - {"title"}:
        snap.gaps.add(("unsupported-annotation", scope))
    execution = tool.get("execution", {})
    require(isinstance(execution, dict), "malformed-execution")
    if execution.keys() - {"taskSupport"} or execution.get("taskSupport", "forbidden") not in (
            "forbidden", "optional", "required"):
        snap.gaps.add(("unsupported-execution", scope))
    meta = tool.get("_meta", {})
    require(isinstance(meta, dict), "malformed-tool-meta")
    if meta.keys() - {ALIAS_KEY}:
        snap.gaps.add(("opaque-tool-meta", scope))
    aliases = meta.get(ALIAS_KEY, [])
    require(strings(aliases) and len(aliases) <= LIMITS["aliases_per_tool"]
            and all(label(a) for a in aliases), "malformed-aliases")
    _icons(tool.get("icons", []))
    _schema(tool["inputSchema"], snap.gaps, scope)
    if "outputSchema" in tool:
        _schema(tool["outputSchema"], snap.gaps, scope)


def snapshot(raw: bytes, budget: Budget) -> Snapshot:
    doc = parse(raw, LIMITS["snapshot_bytes"], budget)
    keys = {"schema", "protocolVersion", "provenance", "servers"}
    fields(doc, keys, keys, "unsupported-snapshot-envelope")
    require(doc["schema"] == SNAPSHOT and doc["protocolVersion"] == VERSION,
            "unsupported-snapshot-version")
    prov = doc["provenance"]
    fields(prov, {"stream", "sequence"}, {"stream", "sequence", "previousSha256"},
           "unsupported-provenance")
    require(label(prov["stream"]) and type(prov["sequence"]) is int and prov["sequence"] >= 0,
            "malformed-provenance")
    if "previousSha256" in prov:
        require(isinstance(prov["previousSha256"], str) and bool(HEX.fullmatch(prov["previousSha256"])),
                "malformed-predecessor-digest")
    snap = Snapshot(prov["stream"], prov["sequence"], prov.get("previousSha256"))
    require(isinstance(doc["servers"], list) and len(doc["servers"]) <= LIMITS["servers"],
            "server-count-or-shape")
    page_count = 0
    for entry in doc["servers"]:
        fields(entry, {"id"}, {"id", "serverInfo", "result", "pages"}, "unsupported-server-envelope")
        server = entry["id"]
        require(label(server) and server not in snap.servers, "ambiguous-server-identity")
        scope = alias("server", server)
        info = entry.get("serverInfo", {})
        if "serverInfo" in entry:
            fields(info, {"name", "version"}, {"name", "version", "title", "description",
                                              "icons", "websiteUrl"}, "unsupported-server-info")
            require(all(isinstance(v, str) for k, v in info.items() if k != "icons"),
                    "malformed-server-info")
            _icons(info.get("icons", []))
        snap.servers[server] = info
        require(("result" in entry) != ("pages" in entry), "ambiguous-list-result")
        pages = entry.get("pages", [{"cursor": None, "result": entry.get("result")}])
        require(isinstance(pages, list) and bool(pages), "missing-list-pages")
        page_count += len(pages)
        require(page_count <= LIMITS["pages_per_snapshot"], "page-count-limit")
        cursor = None
        seen: set[str] = set()
        for index, page in enumerate(pages):
            fields(page, {"cursor", "result"}, {"cursor", "result"}, "malformed-list-page")
            require((index == 0 or cursor is not None) and page["cursor"] == cursor,
                    "broken-cursor-chain")
            result = page["result"]
            fields(result, {"tools"}, {"tools", "nextCursor", "_meta"}, "unsupported-list-result")
            require(isinstance(result.get("_meta", {}), dict), "malformed-result-meta")
            if result.get("_meta"):
                snap.gaps.add(("opaque-result-meta", scope))
            cursor = result.get("nextCursor")
            if "nextCursor" in result:
                require(isinstance(cursor, str) and cursor not in seen, "broken-cursor-chain")
                seen.add(cursor)
            require(isinstance(result["tools"], list), "malformed-tools-list")
            for tool in result["tools"]:
                _tool(tool, server, snap)
        require(cursor is None, "incomplete-pagination")
    return snap
