# MCP Bloodhound v1

MCP Bloodhound compares two local captures of `tools/list` results. The operator selects the approved baseline and the candidate. Findings identify observable changes or phrases for a human reviewer. The scanner has no transport client, process launcher for inspected configurations, model integration or authorization interface. Ground Truth and HERCULES remain independent private systems.

## Run an inspection

Use Python 3.11+ on a POSIX system with descriptor-relative file access and Git. Run the CLI from an editable WolfTrap installation, or substitute `PYTHONPATH=src python -m wolftrap` for `wolftrap` from the checkout. Bloodhound verifies the tracked scanner package against its Git blobs to record a commit and tree. An installation without that checkout returns `INCONCLUSIVE`.

```bash
wolftrap scan-mcp --baseline examples/mcp/baseline.json \
  --baseline-sha256 8c237f492ac371509368e0ad29861e0f414b5a3ea17a443bc7f06543eca28b9a \
  --candidate examples/mcp/candidate.json --output-dir /tmp/mcp-review
wolftrap verify-mcp --baseline examples/mcp/baseline.json \
  --baseline-sha256 8c237f492ac371509368e0ad29861e0f414b5a3ea17a443bc7f06543eca28b9a \
  --candidate examples/mcp/candidate.json --evidence-dir /tmp/mcp-review
```

The example adds an operation to a read-only catalog tool and includes an approval claim. Both commands return 1. Supply the same optional `--config` and `--baseline-sha256` to both commands. Keep the inputs in dedicated local directories. Select a fresh or empty output directory outside all input directories. Verification opens existing files read-only.

| Exit | Inspection and inspection replay | Synthetic challenge and challenge replay |
| --- | --- | --- |
| 0 | `NO_PATTERN_MATCH` within the supported profile | `PASSED_BOUNDED` against authored expectations |
| 1 | `REVIEW_REQUIRED` | `CONTROL_GAP` for a mismatched expectation or an undetected defective classifier |
| 2 | `INCONCLUSIVE` for unsupported coverage, malformed inputs, an unsafe path or untrustworthy evidence | Incomplete or inconsistent evidence, unsupported execution environment |

Coverage gaps take precedence over review signals. The JSON report retains observations made before a bound was reached. A successful replay of a review-required report prints `VERIFIED_EVIDENCE REVIEW_REQUIRED` and returns 1. A malformed path, failed source check or unsafe output destination can prevent publication altogether.

## Snapshot and identity

WolfTrap uses a versioned **capture envelope** around the MCP result object. The normative tool fields, execution metadata and default JSON Schema dialect come from the stable 2025-11-25 specification. Supply the response's `result` member. [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) · [MCP schema](https://modelcontextprotocol.io/specification/2025-11-25/schema) · [Examples](../examples/mcp)

```json
{
  "schema": "wolftrap.mcp-tools-snapshot/v1",
  "protocolVersion": "2025-11-25",
  "provenance": {"stream": "fictional-lab", "sequence": 1},
  "servers": [{
    "id": "fictional-index",
    "serverInfo": {"name": "catalog", "version": "1.0"},
    "result": {"tools": [{"name": "lookup", "inputSchema": {"type": "object"}}]}
  }]
}
```

- The custodian assigns a stable server `id` from its own inventory. A tool identity is the pair of server ID and exact tool name. The optional captured `serverInfo` describes the server. A release changing only its version updates the recorded metadata digest.
- `stream` names a capture series. `sequence` is a nonnegative integer. Both sources must belong to the same series. A lower candidate sequence or different bytes at the same sequence makes comparison inconclusive. Comparing a capture with itself is supported.
- An advancing candidate may include `provenance.previousSha256` with the SHA-256 of the exact baseline file bytes. A mismatch makes the pair inconclusive. The independent optional CLI baseline pin can catch replacement of the baseline before initial inspection. The custodian must retain the latest approved digest separately to establish freshness. A consistently replaced pair can otherwise satisfy every self-declared lineage check.
- For a paginated capture, replace the server's `result` with `pages`, an ordered array of objects containing `cursor` and `result`. Start with a null cursor. Each subsequent cursor must equal the preceding `nextCursor`. The terminal result omits `nextCursor`. Missing pages, repeated cursors and duplicate tool identities fail closed. A terminal result alone cannot establish that the collector retained the entire inventory.
- Tool fields cover `name`, optional `title` and `description`, `inputSchema`, optional `outputSchema`, `annotations`, `execution.taskSupport`, `icons` and `_meta`. Icon metadata participates in drift checks. All icon resources stay opaque. The optional WolfTrap extension `_meta["org.wolftrap/aliases"]` accepts a bounded array of display aliases. Other nonempty tool or result metadata extensions produce a coverage gap. Unknown protocol versions, tool fields and annotations also produce gaps.
- Input and output schemas require an object-typed root. The supported 2020-12 subset covers `type`, `properties`, `required`, `additionalProperties`, `items`, `enum`, `const`, ordinary numeric and length/count bounds, `uniqueItems`, `readOnly`, `writeOnly`, `deprecated`, `title`, `description`, `examples` and `default`. The canonical explicit 2020-12 dialect URI and the MCP default are accepted. References, patterns, composition, unevaluated properties, other dialects and unrecognized keywords produce gaps. Some comparisons between a named property and a schema-valued fallback also produce gaps. The comparison measures local constraints. Schema satisfiability and target argument validation remain outside its scope.

## Review rules

| Rule | Observable basis | Possible benign explanation |
| --- | --- | --- |
| WT-MCP-001 | An instruction-override phrase or a request for a secret category in a candidate metadata field | Quoted examples in a manual |
| WT-MCP-002 | A server identity, tool or field added, removed or changed. Field observations bind before/after digests. A rename appears as removal and addition. | Maintainer release, corrected description or retired tool |
| WT-MCP-003 | Newly visible filesystem, network, credential, write or destructive vocabulary, a relaxed behavior hint, or a wider constraint on a related input | Approved feature or schema correction |
| WT-MCP-004 | Tools on distinct servers share a normalized name, title, annotation title or explicit display alias | Independently named catalog tools |
| WT-MCP-005 | Metadata claims system, developer, administrator, vendor or user authority or contains a recognized structured approval field | Approval glossary or test fixture |
| WT-MCP-006 | A local schema constraint broadens, a schema behavior hint changes, or the declared output contract disappears | Compatible API upgrade or a corrected output contract |
| WT-MCP-007 | A read-only or non-destructive claim accompanies write/destructive vocabulary, or both read-only and destructive hints are explicitly true | Preview behavior, or a client that ignores the destructive hint when reading |
| WT-MCP-008 | A selected stdio configuration declares an inline interpreter switch, an entire filesystem root argument, or a literal under a credential-shaped environment key | Trusted local wrapper or fictional placeholder |

Each signal includes its field, scope, basis, limitation and possible benign explanation. Encoded text inspection covers Unicode NFKC, case folding, format-character removal, percent-encoded UTF-8 and one explicitly labelled `base64:` UTF-8 string. Name matching additionally removes separators and recognizes a small fixed set of visually similar characters. Paraphrases, other languages, unlabelled encodings, unseen confusables and changes in server-side implementation can escape these rules. An unchanged suspicious description can still match a static rule.

### Optional local configuration

`--config FILE` selects the explicit JSON shape below. Every listed key under `mcpServers` must match a candidate server ID. The only accepted entry fields are a nonempty `command`, optional string array `args` and optional string-valued `env` object. Shell interpretation, interpolation, environment lookup and command execution are outside inspection. HTTP transports and additional client-specific configuration fields yield exit 2. Unselected configurations are outside the report's scope.

```json
{"mcpServers":{"fictional-index":{"command":"fictional-indexer","args":["--catalog","sample"]}}}
```

## Bounds and evidence

The parser rejects duplicate decoded keys, invalid UTF-8, lone surrogate code points and nonfinite numbers. Numeric tokens must round-trip through the decimal spelling of a binary64 value and have magnitude at most 2⁵³ − 1. The byte limit applies before decoding. A string-aware pass bounds nesting and structural complexity before JSON object construction. Source-supplied regular expressions and schema references remain inert.

| Resource | Limit |
| --- | ---: |
| Each snapshot / optional config | 256 KiB / 64 KiB |
| Per-file nesting / JSON nodes including keys | 32 / 8,192 |
| Characters per string / absolute path components | 8,192 / 64 |
| Servers / tools / pages per snapshot | 32 / 128 / 64 |
| Additional display aliases per tool | 16 |
| Shared work units / findings per comparison | 65,536 / 256 |

Work units charge input bytes, parsed nodes, metadata text and comparison steps. Input selection uses descriptor-relative opens with symlink rejection on every component and bounded reads of regular files. Inspection rereads the selected bytes before publication. Evidence files use exclusive creation and the manifest is written last. Concurrent writers and partially written bundles cannot silently replace a prior complete report.

Each scan writes `mcp-scan.json`, `mcp-scan.md`, `mcp-scan.sarif` and `mcp-scan.manifest.json`. The JSON records the revision, configuration, digests of exact input bytes, pseudonymous server and tool inventories, field digests, findings and coverage gaps. The equivalents for qualification use the `mcp-challenge` prefix. An unsigned SHA-256 manifest gives byte integrity relative to a known reference. Publisher authentication and capture provenance require independent records.

Identifiers use SHA-256 of canonical compact UTF-8 JSON arrays. A tool alias uses `["tool",server_id,tool_name]` with the prefix `tool-`. This lets an authorized reviewer map a finding locally. Dictionaries and low-entropy names can be guessed from unsalted digests. The public reports contain scanner-owned language and aliases. Keep raw snapshots, configs and identity mappings under the custodian's control.

Verification regenerates the expected reports from the explicit input files and the recorded scanner revision, then compares every byte, including the manifest. Changed inputs, altered or substituted reports, recomputed untrusted manifests, extra files, missing files and symlinked members fail verification.

## Reproduce qualification

```bash
wolftrap challenge-mcp --output-dir /tmp/mcp-challenge
wolftrap verify-mcp-challenge --evidence-dir /tmp/mcp-challenge
```

The corpus has 68 positives, 44 negatives, 26 ambiguous changes, 33 incomplete inputs, three benign matches and four known misses. Labels specify the full expected rule set, exit code and any expected coverage reason. One known miss pairs ordinary metadata with an author-assigned hidden-behavior scenario. Twelve additional controls exercise real local filesystem and evidence behavior using disposable synthetic files. Seven deliberately defective classifiers include an always-alert and an always-clean classifier. Each must fail at least one authored control.

The qualification workflow runs from the exact PR head in a loopback-only namespace with an empty inherited environment and dropped privileges. It replays the synthetic review fixture, a negative fixture and the challenge, generates all three bundles a second time, and compares all twelve files. Only the explicitly screened artifacts are selected for upload. The existing independent research workflow exercises the full regression and research suites. These observations describe the authored corpus and captured inputs. Live protection, private runtime conformance and server compromise require separate evidence. [Qualification script](../scripts/qualify-mcp.py) · [Workflow](../.github/workflows/mcp-qualification.yml)
