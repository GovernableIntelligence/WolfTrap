# Install WolfTrap and review a local project

The offline product candidate adds `doctor`, `quickscan`, `verify-report`, `list-rules` and `--version`. It uses two existing static detectors on selected JavaScript/TypeScript and Markdown files. The core requires Python, a local filesystem and an independently checked wheel. Personal and commercial use remains free under Apache-2.0. The CLI requires no account, network, API key, model, telemetry, Docker or administrator privileges. [License](../LICENSE) · [Readiness baseline and gap owners](product-readiness.md)

## First scan

Use a trusted CPython 3.12 installation with `venv` and `ensurepip`. Download or transfer the qualified candidate ZIP for the exact commit you intend to evaluate. Extract it in a trusted directory owned by you and start there. The `kit/` directory contains the wheel, a CycloneDX 1.6 core SBOM and `SHA256SUMS`. Compare the wheel's SHA-256 with an independently obtained value before installing. The PR qualification records the digest and exact source tree. The bundled checksum list alone cannot authenticate a publisher.

```bash
kit="$PWD/kit"
wheel="$kit/wolftrap-0.5.4.dev1-py3-none-any.whl"
read -r -p "Trusted wheel SHA-256: " pin
work=$(mktemp -d)
printf '%s  %s\n' "$pin" "$wheel" | sha256sum --check --status &&
  (cd "$kit" && sha256sum --check SHA256SUMS) &&
  python3.12 -m venv "$work/venv" &&
  "$work/venv/bin/python" -I -m pip --isolated install --disable-pip-version-check \
    --no-index --no-deps --no-cache-dir "$wheel"
wt="$work/venv/bin/wolftrap"
"$wt" doctor
"$wt" quickscan --demo --output-dir "$work/first-review"
"$wt" verify-report --demo --evidence-dir "$work/first-review"
```

Continue only after checksum verification and installation succeed. A ready doctor prints the installed source commit and tree. The demo contains a fictional approval stub. Its expected scan exits 1 and reports `WT-AGENT-002` on line 2 of `review.js`. Open `$work/first-review/quickscan.md` for the explanation. Successful replay exits 0. The same commands work offline after transfer. [Example source](../src/wolftrap/data/product-demo/review.js)

Select a project you own or have permission to inspect. Install the trusted interpreter and virtual environment outside that project. Source and output must be disjoint. Use a new output name beneath an existing private directory you control. The system temporary directory is also supported. Keep your environment, original evidence, scan selection, wheel and independently retained manifest digest for replay.

```bash
"$wt" quickscan --root /path/to/your/project --output-dir "$work/project-review"
"$wt" verify-report --root /path/to/your/project --evidence-dir "$work/project-review" --show-paths
"$wt" list-rules
```

To limit consent to specific files, repeat `--file` using root-relative names on **both** commands. For example, add `--file README.md --file src/agent.ts`. Replay can also check a separately retained `--manifest-sha256 HEX`. Without that pin, replay establishes agreement with the current inputs and installed engine. It cannot detect an attacker who replaced both the original report and inputs with a new matching set. No chronology, ownership, identity, current permission or actual protected effect is established by a file digest.

| Outcome | Meaning | Next action |
| --- | --- | --- |
| `NO_PATTERN_MATCH`, scan exit 0 | All selected, in-profile input was inspected and no supported rule matched. | Read the coverage and limits before drawing conclusions about the project. |
| `REVIEW_REQUIRED`, scan exit 1 | A documented static condition matched. | Review the file, line and rule. Establish context and reachability separately. |
| `INCONCLUSIVE`, exit 2 | Missing or unsupported input, unsafe path, resource limit, changed installation/source, unreliable replay or coverage gap. Available findings remain visible when the underlying inventory is stable. | Read the reason. Correct the input or choose an explicit supported subset and a fresh destination. |
| `REPRODUCED` | Replay regenerated and matched all four files. Complete results exit 0, including review findings. Reproduced incomplete evidence exits 2. | Keep the original artifact and trusted pin. Investigate a mismatch before using the report. |

## Coverage and privacy

| Check | Selected formats and rule IDs | What remains unknown |
| --- | --- | --- |
| Agent boundaries | Visible `.js .jsx .ts .tsx .mjs .cjs` files. WT-AGENT-001 guardrail error fallback, 002 unconditional authentication/approval callback, 003 session value at a browser-visible sink. | Bounded lexical patterns. A demo callback can look dangerous. Indirect or unrecognized functions, configurations and runtime behavior can evade these checks. |
| Document instructions | Visible `.md .mkd` documents. WT-PROMPT-001 instruction override, 002 instruction disclosure, 003 priority claim with another directive, 004 credential-transfer request. | Fenced or quoted text is intentionally excluded; multilingual, indirect and encoded instructions can be missed. No text is executed. |
| Outside this profile | Build YAML, Go, arbitrary Python, JSON feeds, images and other types count as unsupported when discovered. Legacy standalone scanner/challenge commands retain their own scopes. | A mixed project produces exit 2 if discovery encounters unsupported regular files. Use an explicit subset to request a narrower verdict. Missing optional engines are never interpreted as a pass. |

Discovery skips hidden paths (including Git metadata), vendored dependencies, virtual environments, caches and conventional credential-store names. Excluded entries are counted; their contents are outside consent. Symlinks, hard-linked inputs, special files and nested mounts cannot supply a clean finding. The scanner reads only this local project, its own installation and OS metadata needed for safe file access. It has no automatic remediation, external lookups, account storage, per-user identifiers or enforcement hook. File contents can contain arbitrary sensitive data even under ordinary names. Reports omit excerpts, secrets and raw file names. SHA-256 file and name identifiers are stable and can reveal matches to someone who guesses an input. Keep evidence under your own access controls. `--show-paths` explicitly displays escaped relative names only on your local terminal.

The primary report is versioned JSON with selected input digests, rule IDs, fixed observational basis, line numbers, exact source commit/tree, build record digest, limits and coverage gaps. Markdown gives the next action. SARIF 2.1.0 supports tooling. Each finding is a static review signal with conditional confidence, unrated severity and unassessed identity. The SHA-256 manifest binds the three reports. Independent replay re-reads the same input twice, checks the installed code, and regenerates all four files, including the manifest; changing a file and rehashing a forged manifest cannot reproduce a different analysis over the original inputs.

Per-pass bounds are 512 directory entries, 32 selected files, eight directory levels, 32 KiB/file, 256 KiB total, 2,048 characters/line and 128 findings. Duplicate selections and non-UTF-8 input are incomplete. The product does not parse JSON targets or execute project code, hooks or instructions. For an oversized repository, use `--file` to narrow the scope. For an interrupted output, preserve or inspect that directory and retry with a new name.

## Platform and qualification

The initial matrix targets **Ubuntu 24.04 x86-64 and arm64 with CPython 3.12.14**. A combination earns supported status only with a successful installation, scan, tamper check, replay and uninstall on its matching runner at the selected commit. Read the two matrix results and their exact OS, architecture and Python patch values. The wheel tag describes Python packaging compatibility; product qualification is narrower. Other Linux distributions and Python 3.12 patches can satisfy the runtime feature probe and still lack matching hosted product evidence. Python 3.11/3.13, macOS, Windows and a standalone binary are unsupported for this profile. An editable checkout lacks the product build record; doctor explains how to install the candidate wheel. Historical commands keep their previous requirements. [Product matrix and artifacts](https://github.com/GovernableIntelligence/WolfTrap/actions/workflows/product-qualification.yml)

Each job builds the wheel twice from immutable Git blobs and compares bytes. Three fresh virtual environments install from a local wheelhouse, run doctor, scan, replay, uninstall and reject an incorrect digest. The runner measures elapsed time, CPU seconds and Linux peak RSS, including a 256 KiB corpus scan. The ten-minute target concerns automated local installation through a first completed scan with Python and wheel already present. Network transfer, Python preparation and human onboarding are outside that measurement. No human usability pilot, production false-positive rate, false-negative rate or performance SLA has been established. The published `controls.json` identifies individual authored positives, benign controls, an intentional mock flagged for review, an unrecognized callback missed, incomplete inputs and counterexamples to defective implementations.

## Threat model, review and recovery

| Boundary or failure | Control and qualification evidence | Residual assumption |
| --- | --- | --- |
| Malicious repository, links, traversal, files replaced during inspection | Linux directory descriptors, no-follow walks, single-link regular files, mount IDs, O_PATH inode pinning, metadata/byte checks and a second inventory pass. Tests inject changes, links, FIFOs, traversal and size limits. | The kernel, procfs, local filesystem and machine are trusted. This is a bounded sample of a changing project. Hostile administrators, same-user processes controlling the installation, network filesystems and adversarial mount namespaces are outside scope. |
| Source leakage or unintended effects | Read-only project descriptors, credential-store exclusions, fixed findings, hashed paths, JSON-escaped opt-in local names. The installed CLI is exercised from a project with Python startup/import canaries. | Run the installed executable in a trusted virtual environment. Do not set PYTHONPATH or install interpreter startup hooks from the inspected project. |
| Stale, forged, partial or concurrent reports | Exclusive new output directory, 0600 files, manifest written last, fsync, replay of every artifact, optional independent pin and conflict tests. | The caller owns the output parent. A party controlling every local input and trust pin can substitute history. Different projects with identical selected paths and bytes cannot be distinguished. |
| Supply-chain substitution | Approved build-only wheel with exact digest, Git object selection, PEP 427 RECORD checks, payload-to-source comparison, repeatable wheel and minimal CycloneDX core SBOM. Doctor compares installed package files with the source-bound record. | CPython, pip, runner image and OS are platform prerequisites. A locally replaced verifier or a digest obtained solely from an attacker cannot authenticate the publisher. |
| Host privilege or cross-tenant actions | The product holds no agent grants, tenant state, shared registry or effect adapter. Scope comes from the caller on that machine. | Runtime authentication, tenant authorization and protected effects require independently authorized systems. |

For recovery, uninstall with `"$work/venv/bin/python" -I -m pip uninstall wolftrap`, then install the independently pinned wheel into a fresh virtual environment and replay the original evidence. Keep prior qualified bytes, pins and environments separately. The candidate supports reproducing evidence for its own v1 schema and exact build. No prior product release, automatic updater, cross-version migration, public signed release or global blacklist is supplied.

## Build and supply-chain review

The maintainer build calls the existing setuptools backend on a staging directory populated only from the selected commit. The sole product build wheel is setuptools 84.2.1 (MIT), pinned in the dedicated lock and checked again before use. PyPI listed no advisories for that version at the baseline review date. This is a time-bounded dependency review. The optional PyYAML build-scanner dependency is absent from the installed quickscan profile. The core SBOM inventories the distributed runtime component and explicitly excludes the interpreter, build tools and optional extras. Source screening adds an exact-content check for the new builder lock. Existing dependency and workflow restrictions still apply. [Reviewed build lock](../.github/product-builder.lock) · [setuptools 84.2.1](https://pypi.org/project/setuptools/84.2.1/)

```bash
# Maintainer preparation, outside the offline test: obtain the reviewed wheel once.
python3.12 -I -m pip --isolated download --no-deps --only-binary=:all: --require-hashes \
  --index-url https://pypi.org/simple -r .github/product-builder.lock --dest "$work/tools"
# Use a trusted checkout and a separately confirmed full commit SHA.
python3.12 -I scripts/build-product.py --expected-head "$commit" --wheelhouse "$work/tools" --output-dir "$work/rebuild"
parent=$(readlink /proc/self/ns/net)
unshare -Urn -- env -i PATH="$PATH" PYTHONDONTWRITEBYTECODE=1 python3.12 -I scripts/qualify-product.py \
  --expected-head "$commit" --wheelhouse "$work/tools" --parent-netns "$parent" --output-dir "$work/qualification"
```

| Reference | Implemented or exercised here | Before a production release |
| --- | --- | --- |
| NIST SSDF SP 800-218 v1.1, PS.1–3 and PW.6–8 | Immutable source selection, reproducible product wheel, archived hashes, adversarial tests and a documented disclosure route. | Separately authenticated artifacts and durable, protected release provenance; ongoing vulnerability response. |
| OWASP Top 10 for Agentic Applications 2026, ASI01/02/03/04/05 | Metadata is inert; no tool invocation, identity grant, target execution or mandatory service. Boundaries and negative controls are explicit. | Independent review of the actual deployment and datasets. ASVS 5.0 web application controls require a separately scoped web service. |
| OpenSSF Scorecard, Pinned-Dependencies, Token-Permissions and Code-Review | Immutable Action references, contents-read jobs, no persisted checkout credentials, an exact build-tool hash and draft review. | Maintainer sign-off, independent branch-protection review, signing and a sustained Scorecard assessment. |
| SLSA v1.2 Build track | Build input commit/tree, tool pin and reproducible output digest are recorded and independently comparable. | Authenticated build provenance, trusted builder identity, policy verification and release retention. No SLSA level or certification is claimed. |

Doctor checks the source-listed installed package files. Python startup hooks, additional files placed by a local administrator, and the verifier itself require an independently trusted environment. A release-signing candidate is a Sigstore/Cosign bundle binding the wheel digest to a pinned builder identity, source commit and provenance. An offline subscriber would need trusted roots and a verified transparency-log inclusion proof. No such release identity or signed bundle has been qualified here.

Release verdict **CONDITIONAL for offline evaluation; BLOCKED for production release**. A maintainer and independent reviewer must review the exact candidate, threat model, release identity, signing/provenance, host assumptions and remaining supported-platform gaps. Product naming and clearance are tracked separately. [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) · [OWASP agentic applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md) · [SLSA Build track](https://slsa.dev/spec/v1.2/build-track-basics) · [Issue #21](https://github.com/GovernableIntelligence/WolfTrap/issues/21)
