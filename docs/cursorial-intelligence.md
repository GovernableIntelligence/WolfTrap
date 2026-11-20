# Cursorial Intelligence Engine v1

Cursorial follows a fictional operation from a catalog observation and an agent proposal through host-attested delegation, two authorization decisions and a separately recorded effect window. It answers three questions. Which events can be linked? What should the host have decided at each boundary? What did the synthetic executor actually write?

## Run and verify

Use Python 3.11+ on POSIX with an editable WolfTrap checkout and Git. From the repository, `PYTHONPATH=src python -m wolftrap` is equivalent to the installed `wolftrap` entry point. Use a fresh or empty local output directory. Keep it outside the directory containing a selected input.

```bash
wolftrap challenge-cursorial --output-dir /tmp/cursorial-qualification
wolftrap verify-cursorial --evidence-dir /tmp/cursorial-qualification

wolftrap challenge-cursorial --chain examples/cursorial/authorized.json \
  --output-dir /tmp/cursorial-selected
wolftrap verify-cursorial --chain examples/cursorial/authorized.json \
  --evidence-dir /tmp/cursorial-selected
```

The first pair runs and replays the built-in experiment. The second analyzes one explicitly selected fictional capture and derives six variations of its first committed binding. Supply the exact original file for replay. Both commands accept `--expected-head` with a full commit ID obtained from a trusted record. The engine compares tracked package bytes with the commit's Git blobs. It needs its source checkout for that check.

| Exit | Qualification | Selected capture |
| --- | --- | --- |
| 0 | All bounded authored expectations and defect controls qualified | Complete synthetic behavior agreed with the independent oracle and reproduced on fresh state |
| 1 | A control failed qualification | Metadata-only evidence raised a static review signal |
| 2 | Unsafe path, unusable source identity or unverifiable bundle | Incomplete, contradictory or unsupported evidence, unreproduced observations, or incomplete variation coverage |

Replay preserves the underlying exit code. The JSON retains the original capture verdict separately when a derived variation hits a bound. A complete behavioral trace can include static advisories alongside a verified legitimate effect or a verified denial.

## What each stage uses

| Stage | Evidence and operation |
| --- | --- |
| SCENT | Validate the closed capture schema. Typed catalog indicators and agent claims produce source-scoped static review signals. |
| TRACK | Anchor the chain in a host-owned opening record. Follow explicit event IDs, host-bound tenant and actor, delegation parents, namespaced tool and schema revision, operation digest, logical order, replay slot and recovery checkpoints. |
| PURSUE | Make fresh deterministic schedules for forged approval, a substitute server, a foreign tenant's grant, a different chain's grant, revocation after preparation and replay. Each variation binds its parent schedule digest. |
| SURROUND | Compare the host's prepare/commit witnesses with a separate snapshot of the synthetic executor's append-only ledger. Check the entire typed delta, including the operation actually written. |
| CONFIRM | Reconstruct expected authority independently at each decision time. Re-run discrepancies twice on fresh host and ledger state, remove individual schedule events while retaining the same discrepancy fingerprint, then run the reduced schedule twice more. |

### Authoring a fictional capture

The envelope uses `schema: wolftrap.cursorial-chain/v1`, a `mode` of `behavior` or `metadata`, and four fixed source channels. Each channel contains its fixed source alias and an ordered `events` array. Channel membership controls the permitted record types. The schema accepts small integer aliases and enumerated operations. Free-form prompts, commands, URLs, credential values and customer names are outside the input language. [Complete delegated example](../examples/cursorial/authorized.json) · [Chain JSON Schema](../src/wolftrap/schemas/cursorial-chain-v1.schema.json)

| Channel | Records | Interpretation |
| --- | --- | --- |
| Catalog | `tool_definition_observed` | Server, tool, schema revision and a pre-normalized indicator. A catalog cannot issue a grant. |
| Agent | `agent_proposal` | Proposed typed operation, claimed grant and slot, definition reference and optional approval/success claim. |
| Host | `chain_opened`, `delegation_observed`, `grant_state`, `epoch_observed`, `request_bound`, `gate_decision`, `recovery_checkpoint` | Complete fictional registry, identity, delegation, authority timeline, receipt of the proposal, original and final decision, lost reply, resumption and capture closure. |
| Ledger | `effect_observed` | Independent before/after counts and prefix digests plus the actual newly appended records for one commit. An explicit empty window is the witness for zero writes. |

Every event has a unique ID, logical time and chain alias. Within a capture, logical times are distinct. The operation digest is lowercase SHA-256 of the compact, sorted-key UTF-8 JSON object containing `server`, `tool`, `schema_rev`, `verb`, `resource` and `value`. A slot is single-use within a tenant. Delegation begins at the chain owner. Each host-attested link must continue a specific live parent and satisfy the current epoch and expiry. Grants bind the chain, tenant, grantee, operation, slot, epoch, validity interval and active state. The expiry boundary is exclusive.

A commit requires successful preparation and current authority. A denied preparation followed by new approval requires a new attempt. The host retains spent slots across a lost reply and resumption. Each proposal must have a host binding, both gate decisions and one complete ledger window. The terminal host checkpoint must account for every binding. Missing records, mismatched digests, unresolved tool identities, spliced windows and conflicting host identity make the behavioral assessment inconclusive.

The graph records the role-owned source of each node and typed directed edges between earlier and later observations. Earlier grants and epoch updates connect to the gates that used them. Each commit connects to its ledger window. Consecutive windows bind the same ledger prefix. The ledger prefix is the digest of the ordered array of actual typed receipts. [Graph JSON Schema](../src/wolftrap/schemas/cursorial-graph-v1.schema.json)

### Independence and reproduction

The gate receives a callback for a fictional protected write. A separate witness snapshots WolfTrap's in-memory `SyntheticEffectLedger` on both sides of the commit. Its receipt includes the actual operation preserved at append time. The oracle independently serializes and hashes proposed operations, selects the latest host grant as of each decision, derives reachable delegates from host history, and maintains its own expected consumed slots. Its expected state uses neither reported decisions nor ledger observations.

A disagreement is initially inconclusive. A synthetic control defect requires the same binding-specific fingerprint on fresh runs. The report retains the original witness, exact minimized schedule, before/after event counts, fresh reproductions and the minimization budget. The reduction searches for a single-event deletion that preserves the discrepancy. The report says whether that search finished. An archived claim or a patched report cannot seed a successful replay. Selected captures are replayed through the correct fictional host after stripping all observed outcomes.

### Limits, known false positives and misses

Each selected file is limited to 96 KiB of strict UTF-8 JSON, nesting depth 12, 4,096 nodes including keys, 48 events, 384 graph edges, graph depth 32, four delegation hops and a 128-tick span. The closed schema bounds each ledger delta at four receipts. Duplicate decoded keys, floats, nonfinite values, unknown fields and ambiguous order are rejected. Input and evidence reads use descriptor-relative paths and reject symlinks, nonregular files and multiply linked evidence members. The input bytes are reread before publication and on replay. Each minimization gets at most 64 deletion evaluations.

The 156 authored cases span four host contexts from a direct owner to three-hop delegation. They include 104 complete synthetic chains, 48 deliberately incomplete records and four metadata-only cases. Four benign glossary lookalikes raise an approval advisory. Four author-labelled compromised-session examples have byte-identical observed behavior to their legitimate counterparts. Each correctly illustrates an attribution limit. Neither count estimates a production error rate.

Nine defective host/executor implementations cover blanket allow/deny, trusting approval claims, omitted identity checks, skipped final checks, forgotten replay slots, fabricated success, a substituted effect payload and writes after denial. A separate advisory classifier that flags every chain must fail benign controls, and a silent classifier must miss positive controls. An intermittent control must remain inconclusive.

**Not tested** includes live agents or swarms, genuine runtime authorization, distributed clocks, crash durability, malware identification, human attribution and incident prevention. Fixed channel aliases and unsigned hashes cannot authenticate an external observer. Logical effects are local records in disposable synthetic state. Ground Truth and HERCULES remain private, independent systems. CIE v1 accepts standalone fictional catalog indicators and has no dependency on MCP Bloodhound.

## Evidence and hosted qualification

A bundle contains `cursorial.json` (graphs, independent expectations, host and ledger evidence, outcomes and counterexamples), `cursorial-chains.json`, `cursorial.md`, `cursorial.sarif` and `cursorial.manifest.json`. The qualification archive retains the generated fictional traces. For selected input the archive retains byte length and digests. Raw selected files stay with the operator. Every report member has a byte count and SHA-256 in the manifest, which is published last. Verification regenerates the bundle from the exact source and compares all bytes, including the manifest.

The dedicated workflow checks out the exact PR head without persisted credentials. A loopback-only namespace with a cleared environment runs source screening, isolated tests, both CLI modes and replay. It generates both bundles twice and compares all ten files. A separate qualification routine joins the saved host decisions and effect windows directly to the reported witnesses and authored results. Only the declared, screened evidence is uploaded. The existing independent research workflow covers the full regression suite and the older research vehicles. [Qualification script](../scripts/qualify-cursorial.py) · [Workflow](../.github/workflows/cursorial-qualification.yml)
