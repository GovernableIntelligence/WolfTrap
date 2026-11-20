# Offline product readiness baseline

Assessed 2026-11-20 before product implementation under [charter #20](https://github.com/GovernableIntelligence/WolfTrap/issues/20). The public Apache-2.0 repository's main commit was `ec6c3c1b2a50d702d202bd9b4e40842ba6e395f2`, tree `cfcda2adf37f8862451601d96292f9cbf32e3a7f`. A clean CPython 3.12.14 Linux x86-64 wheel install from this source exposed 33 CLI subcommands. Both proposed product commands exited 2 as unknown commands. Independently rerunning `scripts/qualify-research.py` on this commit in a loopback-only namespace passed 381 tests with zero skips, errors or failures. This is evidence of exercised research behavior. [Original hosted qualification](https://github.com/GovernableIntelligence/WolfTrap/actions/runs/44523418714)

## Availability at baseline

| Main interface | Surface, dependency and evidence | Coverage boundary |
| --- | --- | --- |
| `scan-build`, composite GitHub Action | Selected workflow YAML and root Dockerfile/Containerfile, including artifact paths. Optional PyYAML for the build profile. JSON, Markdown, SARIF, integrity manifest. | Conditional static chains. Dynamic workflow behavior and the runtime trust boundary require other evidence. The hosted Action downloads tooling. |
| `scan-agent`, Python API `verify_agent_evidence` | JS/TS guardrail errors, unconditional authorization callbacks and browser-visible credential sinks. Bounded lexical source inspection. JSON, Markdown, SARIF, manifest. | No whole-program dataflow or runtime authentication. For saved agent challenges use `verify-agent-challenge`. |
| `scan-effects` / `verify-effects` | Selected JS/TS and SKILL.md rule shapes for approvals and protected effects. Standard library. Static report bundle. | Mock callbacks and instruction claims cannot establish a write. |
| `scan-prompts` / `verify-prompts` | UTF-8 Markdown, text, selected JSON values and extensionless documents. Standard library. Redacted static report bundle. | Quoted or obfuscated instructions and other languages can evade lexical rules. |
| `scan-go-authority` / `verify-go-authority` | Explicit Go files, narrow authority and egress patterns. Standard library. Redacted static report bundle. | Dynamic resolution and actual network behavior are outside scope. |
| `scan-cloud-trace` / `verify-cloud-trace` | Explicit pre-sanitized GitHub event-summary JSON. Offline bounded evidence. | No live monitoring, collection or assurance of event provenance. |
| `run`, `sweep`, `reproduce`, `list-scenarios`; build and agent challenges | Versioned local synthetic scenarios, modeled effects, Markdown/JSON, reproduction and manifests. Build-related challenges use PyYAML. | Finite models and deliberately defective implementations. Results do not establish behavior of an external system. |
| Cloud-C2, camouflage, cloud authority, funnel, sandbox authority, ARTEX and GT-VSA challenge/verify commands | Fictional correlated traces, grants, independent ledgers and scenario controls. Additional identity telemetry, prompt trust and authority qualification modules use `python -m wolftrap.MODULE`. | Known benign lookalikes and authored misses. Genuine host authority, identity and production effects remain unverified. |

The earlier local on-ramp uses an editable source checkout or the hosted composite Action. The source declares Python 3.11+ and zero required runtime distributions; `.[build-scan]` adds PyYAML. The historical package version is 0.5.3. The public v0.5.3 research prerelease points at a different source commit, `15d8df6ac3228999294c5d37284e826c53e1b86f`, and has zero attached release assets. Generated source archives are available. No published signed wheel, binary, release SBOM or verified cross-platform end-user installation was established. Existing CI primarily exercises Ubuntu 24.04, including an exact-head network-isolated research job. Filesystem-safe modes depend on POSIX directory descriptors and no-follow semantics. Windows, macOS and Linux arm64 clean product use were **NOT TESTED** at this baseline. [Pre-release](https://github.com/GovernableIntelligence/WolfTrap/releases/tag/v0.5.3) · [Security policy](../SECURITY.md) · [Contribution policy](../CONTRIBUTING.md)

All 26 remote branch tips and their Git parents were inventoried. The six open PRs at baseline were drafts. The counts below are hosted check conclusions at these heads.

| Draft | Head | Parent lineage and baseline status |
| --- | --- | --- |
| #13 MCP Bloodhound | `e1f80816ddc8a05faf2f784dd979a3d08b0b0c48` | Descends from main. Three green checks. Offline MCP snapshot inspection only. |
| #14 Cursorial | `02dcbdd60a6249590dbf4b2e69d1c207657b537c` | Descends from main. Three green checks. Synthetic causal chains and effects. |
| #16 integration | `80af479d6eb6908de6dc69ea3e7bf533e44cb956` | Two merge parents are the exact #13 and #14 heads. Four green checks. |
| #17 WolfPrint | `0c537d128eb78554dc9fb938d650eb0c532bf48b` | Based on #16. Five green checks. Architecture and fictional issuer evidence. |
| #22 WolfNet (issue #19) | `67d66a93c75e3be881953fd31d50ceab88a7815b` | Based on #17. Six green checks. Signed fictional feeds and scoped proposals. No default enforcement. |
| #18 external runtime research | `4c9e685d428127ca87e9980cab6073420aead12b` | Separate descendant of main. Two green checks, one failed independent-public-qualification check. Excluded from the product. |

## Gap ledger and release decision

VERIFIED means an identified check ran. CONDITIONAL limits that evidence to its named input and environment. NOT TESTED means no matching measurement. BLOCKED identifies a missing release dependency. P0 prevents a public production release, P1 blocks a supported user workflow, P2 limits reach or quality, and P3 is a lower-impact improvement. Owners below are proposed review roles.

| Priority / evidence | Observed gap and user impact | Owner and acceptance criterion |
| --- | --- | --- |
| P0 · BLOCKED for release | No separately authenticated release artifact/provenance, release review or clearance. A source hash alone cannot identify a publisher. | Maintainer and independent release reviewer. Authenticate exact bytes and source, verify from an independent trust root, review known risks, and record approval. Naming clearance is separately tracked in #21. |
| P1 · VERIFIED gap | A first-time user must pick among 33 commands; doctor and quickscan were absent. Editable install instructions may require a network connection. | Product and packaging maintainers. Demonstrate hash-checked offline wheel installation, inspection, replay and uninstall in clean matching environments. |
| P1 · CONDITIONAL | Separate static scans and manifest checks have different coverage and replay contracts. A no-match across a subset can be mistaken for a complete inspection. | Scanner and evidence reviewers. Explicit selection, skipped/incomplete scope, operation-free reads, localized findings, independent replay and tamper controls. |
| P2 · NOT TESTED | Broader OS/CPU/Python coverage, real-project accuracy, accessible user pilots and first-time human performance. | Platform and usability reviewers. Publish real matrix runs and representative consented usability/error measurements before making claims. |
| P2 · CONDITIONAL | Source screening and pinned Actions exist. The historical setuptools minimum and optional PyYAML range are not a reproducible product build recipe. | Build maintainer. Pin and review the candidate build tool, perform independent rebuilds and inventory components. |
| P3 · NOT TESTED | Standalone distribution and optional integrations could reduce setup work. | Product maintainer. Separate proposals after supported core use and review. |

Baseline verdict **BLOCK — RELEASE GATES FAILED**. No independently confirmed production incident is inferred. Candidate qualification, support information and remaining release gates are tracked in the [offline product guide](offline-product.md).
