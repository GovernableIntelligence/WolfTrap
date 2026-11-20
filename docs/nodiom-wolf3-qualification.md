# Wolf #3 — genuine Nodiom local MCP qualification

## Authority and scope

This is a **local-only defensive assessment of public open-source code**. Do not contact `api.nodiom.md`, `nodiom.md`, or `synexiomlabs.com`. No private data or credentials are used. All application builds, tests and runtime calls execute in a non-root, network-disabled container. The workflow installs public dependencies first with npm lifecycle scripts disabled, and does not expose a persisted GitHub token.

Pinned source commits:
- Synexiom-Labs/nodiom: `335de4d79ed9b64e8f679fe13a088c7c503525f0`
- Synexiom-Labs/nodiom-mcp: `469aa971ea0d836d4428f977bd05790168a1fc5f`

## Experiment

The core library test intentionally reads the same synthetic Markdown file into two `Nodiom.fromFile()` objects, applies one distinct append in each copy, then saves them in sequence. It verifies that the last save overwrote the first change. The positive control independently runs eight concurrent operations using `Nodiom.fromFile(file, {lock:true})` and requires all markers to survive.

The MCP harness starts eight **actual pinned MCP stdio server processes**, negotiates `initialize`, captures `tools/list`, and checks that eight serialized local `nodiom_append` operations preserve all markers. It also verifies a benign synthetic absolute-path read to characterize the public adapter's explicitly documented file-path behavior; this is not automatically an authorization vulnerability.

Finally, it sends up to sixteen sets of eight concurrent local `nodiom_append` calls to isolated fabricated Markdown files, each writing a unique marker. An observed MCP lost-update result requires every call to report success, with at least one unique marker missing from the file. A non-reproduction is not a safety certification.

## Evidence and interpretation

The CI artifact contains `source-pins.txt`, `node-image-id.txt`, `core-runtime.json`, `mcp-runtime.json`, `tools-list.json` and `sha256sums.txt` when the corresponding stages complete. Stage failure, missing dependencies, or a skipped job must remain **INCONCLUSIVE**, never be treated as a target pass or finding.

This proves only observed behavior in the named local open-source revisions, not the hosted Nodiom Cloud architecture, production security controls, exploitability or severity. Do not report it as a Cloud compromise. Source-level concerns remain REVIEW REQUIRED until actual test evidence is inspected.

The Docker image uses a mutable tag `node:22-bookworm-slim`; its resolved image ID is retained for post-run provenance review. The hosted runner and npm registry are dependencies of the qualification environment, so this is not a comprehensive supply-chain assurance exercise.

No merge, deployment to users, or public vendor disclosure is part of this workflow.
