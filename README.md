# WolfTrap

**The wolf follows the evidence. Authority does not follow the herd.**

<img src="docs/assets/wolftrap-canadian-wolf.jpg" alt="Original Canadian grey wolf illustration for WolfTrap" width="460">

WolfTrap is public defensive security research from Governable Intelligence.
The Canadian grey wolf is the project's unofficial mascot. WolfTrap has no FBI
affiliation or endorsement.

WolfTrap is a **read-only, offline trust-boundary inspector** for GitHub
Actions, Dockerfiles, bounded JavaScript/TypeScript agent code, and Stage 5.2
protected-effect boundary patterns across agent skills and scripts. Stage 5.3
adds a separate prompt-document mode for untrusted README and prompt files.
An opt-in Go source mode checks four conditional permission, subprocess, proxy,
and optional-gate patterns. Separate independently labelled synthetic
challenge labs test the detectors without
contacting external systems. WolfTrap identifies *conditional review signals*,
explains the contributing conditions, and produces portable JSON, Markdown,
SARIF and integrity manifests. No inspected project code is executed.

An additional **experimental cloud-C2 synthetic challenge** models two bounded
behavioral correlations inspired by publicly documented GitDoor activity. It
does not scan live GitHub repositories, diagnose infections, or interact with
command-and-control services.

**Evidence boundary.** Static matches are `STATIC REVIEW SIGNAL`. Passing
deterministic lab results are `SYNTHETICALLY VERIFIED` for their exercised
cases. Unsupported input or incomplete evidence is `INCONCLUSIVE`.
Live ARTEX threat detection, production control effectiveness and Ground Truth
runtime conformance are `NOT TESTED`. The Go mode does not change that.
`LIVE VERIFIED` requires separate,
independent evidence from a named, authorized genuine implementation.

- Reproduce the [offline authority demo](docs/evaluation-demo.md).
- Review the [security architecture](docs/security-architecture.md),
  [evidence guide](docs/evidence-guide.md), and [agency technical brief](docs/agency-technical-brief.md).
- Check the [verified public baseline and evaluation priorities](docs/qualification-baseline.md).
- Read the [proposed private runtime conformance contract](docs/private-runtime-conformance.md)
  or the [responsible-disclosure process](SECURITY.md).

Licensed under the [Apache License, Version 2.0](LICENSE).

**9 explainable CI/build review rules** currently cover privileged PR execution,
untrusted shell interpolation, mutable actions, unknown token authority,
cross-workflow artifact handling, self-hosted PR runners and risky container
build instructions. Each rule has a bounded scope and an explicit limitation.
**3 separate Stage 5.1 agent signals** cover recognizable fail-open moderation,
unconditional authentication/approval callbacks, and supported session-credential
logging patterns. **13 Stage 5.2 conditional patterns** add agent launch,
host-secret copying, sandbox and network isolation review, browser-managed
keys, skill instructions, API upload controls, and remote fetch bounds. None
establish real-world exploitability. **4 Stage 5.3 prompt-document signals**
triage attempted instruction overrides, governing-prompt disclosure, priority
claims and credential transfers. Ordinary prompt templates are not themselves
verified attacks.
**4 separate Go authority signals** review unconditional permission callbacks,
host-environment subprocess launches, proxy-before-pinned-dial transport ordering,
and optional gate allow-through paths. They do not prove authorization bypasses.

> **Public beta:** The read-only CI/build inspector, Stage 5.1 agent inspector,
> synthetic challenge labs, and community CI/build Action are available on
> `main`. The earlier community Action's
> [hosted qualification passed](https://github.com/GovernableIntelligence/WolfTrap/actions/runs/43663128275)
> at commit `4d1f075dadf257375a0ea59d39dea9151d07e3f5` before this
> documentation update. An empty scan is **not a security certification**.
> Findings are conditional and require human review; there are no confirmed
> external exploits here.

## Run an inspection or synthetic challenge

The offline product candidate provides a hash-checked local wheel, `wolftrap doctor`,
`wolftrap quickscan` and `wolftrap verify-report`. Start with the included two-file
example, then select your own authorized project. [Installation, quick start and tested scope](docs/offline-product.md).

### Option A: Scan your repository locally

Requires Python 3.11+ and a local authorized checkout:

```bash
git clone https://github.com/GovernableIntelligence/WolfTrap.git
cd WolfTrap
python3 -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/YOUR-repository --output-dir /tmp/wolftrap-review
```

The command installs the public beta from the default branch. For repeatable
security reviews, check out a reviewed exact commit rather than following a
moving branch. Use a new/empty output directory **outside** the target
repository.

### Option B: Add the GitHub Action (public beta)

Copy [`examples/wolftrap-scan.yml`](examples/wolftrap-scan.yml) to
`.github/workflows/wolftrap.yml` in **your** repository. It uses a read-only
token, checks out the requested revision without persisting credentials, runs
only WolfTrap's scanner, and retains a report artifact. The example pins a
hosted-qualified Action implementation to an immutable 40-character commit
SHA; review that exact revision before adopting or updating the pin.

Or run the 128-case offline detector challenge yourself:

```bash
wolftrap challenge-build --seed 20261115 --cases 128 --output-dir /tmp/wolftrap-challenge
wolftrap verify-challenge --evidence-dir /tmp/wolftrap-challenge
```

### Option C: Review local JavaScript/TypeScript agent boundaries

Point the separate `scan-agent` command at a local source checkout you own
or have permission to inspect. It accepts selected `.js`, `.ts`, `.jsx`,
`.tsx`, `.mjs`, and `.cjs` files; it does **not** launch the agent,
authenticate users, or call a model or API.

```bash
wolftrap scan-agent --root /path/to/YOUR-agent-source \
  --output-dir /tmp/wolftrap-agent-review
```

The output directory must be new or empty and outside the inspected source.
`WT-AGENT-001`, `WT-AGENT-002`, and `WT-AGENT-003` are conditional static
review signals, **not confirmed vulnerabilities**. An unconditional
authentication callback remains `REVIEW_REQUIRED` even when its name
explicitly indicates a demo/mock; unrelated comments cannot confer mock
context. Unsupported syntax or coverage limits produce `INCONCLUSIVE`.
See [agent rule scope and limitations](docs/agent-inspection.md) and the
[Stage 5.1 quick start](docs/quickstart.md#4-offline-agent-source-review-stage-51).

This bundled **synthetic** repository fixture exercises review of a PR artifact
feeding a privileged consumer:

```bash
wolftrap scan-build --root tests/fixtures/stage4_demo --output-dir /tmp/wolftrap-demo
# REVIEW_REQUIRED: 2 files, 2 review-required signals, 0 unknown inputs
```

**Results:** `NO_PATTERN_MATCH` (0, no *supported* pattern matched),
`REVIEW_REQUIRED` (1, manual triage), or `INCONCLUSIVE` (2, incomplete/unsupported;
never a clean pass). With the GitHub Action's default advisory setting, review
signals leave CI green but **unknown always fails**. Set `fail-on-findings:
'true'` to make known review signals fail CI as well.

### Option D: Stage 5.2 protected-effect boundary review

For a local repository with agent launch code, scripts, or `SKILL.md`
instructions, run the **separate** offline command:

```bash
wolftrap scan-effects --root /path/to/YOUR-agent-repo \
  --output-dir /tmp/wolftrap-effects-review
wolftrap verify-effects --evidence-dir /tmp/wolftrap-effects-review
```

Supported input: bounded JS/TS variants, `.py`, `.sh`, and only files named
`SKILL.md` among Markdown. Use repeated `--file` to select a small review set.
The scanner does not query credential stores or contact endpoints; its evidence
omits any credential literals that may be present in inspected source and
replaces original paths with SHA-256 aliases. It reviews unrestricted CLI flags,
host credential copying, explicit sandbox bypass and broad mounts, browser API
keys, potentially unsafe remote fetches, and skills instructing unauthorized
effects or excessive tool access. An agent skill cannot grant its own authority.
Every finding is `REVIEW_REQUIRED`, never proof of an attack; incomplete
inspection is `INCONCLUSIVE`. The existing community Action continues to run
**only** the CI/build scanner. [Stage 5.2 rule scope and limits](docs/effect-inspection.md).

### Option E: Stage 5.3 untrusted prompt-document review

Use this **separate, offline** command for alleged model prompts, READMEs,
agent-instruction documents, and text tool descriptions:

```bash
wolftrap scan-prompts --root /path/to/YOUR-document-repo \
  --output-dir /tmp/wolftrap-prompt-review
wolftrap verify-prompts --evidence-dir /tmp/wolftrap-prompt-review
```

It inspects bounded `.md`, `.txt`, `.mkd`, `.json` and extensionless UTF-8 text,
including material outside Stage 5.2's strictly named `SKILL.md` scope.
`REVIEW_REQUIRED` (exit 1) means conditional text-level signals, not a
successful injection. `INCONCLUSIVE` (exit 2) means incomplete input; no matches
(exit 0) is not a safety certificate. Source is never executed or sent to a
model. Use `--file README.md` for a focused review; evidence omits original
source text and hashes its paths. This does **not** authenticate alleged vendor
prompt leaks. [Stage 5.3 usage and limits](docs/prompt-inspection.md).

See the [60-second quick start](docs/quickstart.md),
[supported rules and limitations](docs/build-inspection.md),
[responsible disclosure](SECURITY.md) and [contributing guide](CONTRIBUTING.md).

### Option F: GitDoor-inspired synthetic cloud-C2 challenge (research preview)

```bash
wolftrap challenge-cloud-c2 --output-dir /tmp/wolftrap-cloud-c2
wolftrap verify-cloud-c2 --evidence-dir /tmp/wolftrap-cloud-c2
```

The fixed eight-case, offline corpus includes positive and negative behavioral
controls, cross-session isolation, correlation-window expiry, and a separate
authorization-origin test in the unit suite. Its two `WT-CLOUD-C2` signals
are conditional correlations in **pre-normalized synthetic GitHub events**,
not general malware detections. A completed manifest binds JSON and Markdown
evidence to the deterministic test corpus; the verifier independently reruns
the controls. No actual endpoint, file, code sample or credential is contacted,
downloaded or executed. See [scope, threat provenance and limitations](docs/cloud-c2-challenge.md).

### Option G: inspect pre-sanitized GitHub API event summaries offline (research preview)

```bash
wolftrap scan-cloud-trace --root /path/to/sanitized --file events.json \
  --output-dir /path/to/new/evidence
wolftrap verify-cloud-trace --root /path/to/sanitized --file events.json \
  --evidence-dir /path/to/new/evidence
```

**Input is not a GitHub audit-log export.** An authorized upstream analyst must
first reduce trusted endpoint or API-gateway telemetry into a small, strictly
typed JSON record containing only logical event order, opaque session/repo/issue
aliases, and fixed action categories. The command rejects URLs, credentials,
free text, payloads, extra fields and unsafe file paths. It does no collection,
networking or attribution. `REVIEW_REQUIRED` (exit 1) indicates a **conditional**
cross-repository pattern; `NO_PATTERN_MATCH` (exit 0) is not proof of safety;
`INCONCLUSIVE` (exit 2) means unusable evidence. The verifier replays against
the unchanged source file. See [input schema and hostile-test limits](docs/cloud-c2-challenge.md).

### Option H: adversarial cloud camouflage challenge (research preview)

```bash
wolftrap challenge-cloud-camouflage --output-dir /tmp/wolftrap-cloud-camouflage
wolftrap verify-cloud-camouflage --evidence-dir /tmp/wolftrap-cloud-camouflage
```

This **160-case deterministic synthetic corpus** separately measures 40 narrow
positive controls, 40 routine benign negatives, 40 benign automation
lookalikes that nevertheless trigger a rule, and 40 threat-inspired variants
that evade the narrow rules. A passing run means the detector reproduced
these authored expectations. It explicitly **does not** mean 100% threat
coverage or measured production false-positive rates. The input contains
only sanitized event categories and fictional aliases: no real repositories,
executables, payloads, attacker infrastructure or network traffic. See
[what the challenge can and cannot establish](docs/cloud-c2-challenge.md).

### Option I: ARTEX-informed synthetic authority-funnel challenge (research preview)

This separate, entirely offline experiment models a **host-owned grant
registry** under inert untrusted-tool claims, wrong-delegate and cross-tenant
credential reuse, privilege escalation, revocation, and three 1,000-proposal
swarm scenarios. It uses an independently implemented reference model and
positive as well as negative controls. No real accounts, credentials, tool
outputs, model calls, tenants or networks are involved.

```bash
wolftrap challenge-authority-funnel --output-dir /tmp/wolftrap-authority-funnel
wolftrap verify-authority-funnel --evidence-dir /tmp/wolftrap-authority-funnel
```

The 20 authored cases contain 3,019 synthetic proposals. A passing result
means only that these finite model expectations agree; **it does not test or
certify the Ground Truth runtime**, and it cannot identify stolen valid
credentials when the adversary is indistinguishable from an authorized caller.
See [authority-funnel scenario mapping and limitations](docs/authority-funnel-challenge.md).

A separate three-stage [sandbox + authority composition challenge](docs/sandbox-authority-challenge.md)
models fictional host-owned isolation policies and 1,000 synthetic intents per
stage. It **does not launch actual sandboxes, AI agents or protected effects**.

### Option J: independent synthetic authority after cloud advisories

```bash
wolftrap challenge-cloud-authority --output-dir /tmp/wolftrap-cloud-authority
wolftrap verify-cloud-authority --evidence-dir /tmp/wolftrap-cloud-authority
```

Each of the 160 authored cloud traces is crossed with **12 authority conditions**
in WolfTrap's existing synthetic protected-effect system (1,920 checks total).
They include current grants, invalid credentials, foreign origins, scope and
operation-digest mismatches, stale epochs, revocation before and after
authorization/preparation, unknown security state, credential substitution,
and replay. An independently captured effect ledger and a separate reference
oracle establish whether the synthetic protected effect was allowed.

**A cloud alert is advisory, never a grant or revocation.** Likewise a clean
scan cannot create authority. This is **not** a deployed Ground Truth broker,
HERCULES integration, GitHub endpoint protection or real malware detection.
See the [authority separation experiment](docs/cloud-c2-challenge.md).

### Option K: bounded Go authority and egress source inspection

Inspect selected local `.go` files without compiling or running Go:

```bash
wolftrap scan-go-authority --root /path/to/authorized-repo \
  --file server/tool.go --file guard/hooks.go \
  --output-dir /tmp/wolftrap-go-review
wolftrap verify-go-authority --evidence-dir /tmp/wolftrap-go-review
```

Four `WT-GO-*` patterns produce conditional `REVIEW_REQUIRED` signals,
not a confirmed vulnerability. There is no whole-program call graph, runtime
authorization check, Go compilation or automatic production gate. Bounded
failures produce `INCONCLUSIVE`; evidence contains hashed paths, line numbers
and rule metadata. See [Go rule coverage and limits](docs/go-authority-inspection.md).

### Option L: three-stage synthetic sandbox + authority funnel

```bash
wolftrap challenge-sandbox-authority --output-dir /tmp/wolftrap-sandbox-authority
wolftrap verify-sandbox-authority --evidence-dir /tmp/wolftrap-sandbox-authority
```

The three deterministic stages each contain 1,000 typed fictional agent intents.
They check missing/weak sandbox envelopes, out-of-scope filesystem requests,
disallowed network access, missing host approval, invalid delegated authority,
stale/revoked/expired grants and one-slot contention. The effect sink is
captured separately from the gate's success claims, and the evidence verifier
replays the exact bounded scenario. **No operating-system isolation, live
1,000-agent execution or Ground Truth/HERCULES runtime has been qualified.**
See [setup, controls and limits](docs/sandbox-authority-challenge.md).

### Option M: ARTEX-inspired multi-step adversarial chain (synthetic)

```bash
wolftrap challenge-artex-chain --output-dir /tmp/wolftrap-artex-chain
wolftrap verify-artex-chain --evidence-dir /tmp/wolftrap-artex-chain
```

Sixteen fixed offline cases exercise 65 fictional, sequential requests across
reconnaissance, access, privilege and final-effect stages. They challenge
out-of-scope scanning, forged approvals, unauthorized role escalation,
cross-agent and cross-tenant splicing (even with a valid foreign grant),
revocation *after* preparation, expiry,
stale epochs, replay and missing authority. A legitimate four-step chain is
the positive control. Fixed expectations, an independent decision oracle and
an independently captured in-memory effect sink must agree; a denial stops
the remaining chain. **No ARTEX process, network request, exploit, live agent,
real sandbox or Ground Truth/HERCULES runtime runs.** See
[scenarios, reproduction and limitations](docs/artex-chain-challenge.md).

### Additional offline evaluation suites

- Replay six defensive identity-telemetry rules on sanitized synthetic records.
  The corpus includes routine and flagged benign controls, known misses and
  incomplete telemetry. [Identity telemetry challenge](docs/identity-telemetry.md).
- Cross inert prompt and tool-output claims with independently selected host
  authority states. A static match has no bearing on permission.
  [Prompt and tool trust challenge](docs/prompt-trust-challenge.md).
- Compare independently recorded effects with authored expectations across
  phased authority schedules, a 1,000-proposal pressure bound and defective
  sentinels. [Authority qualification](docs/authority-funnel-challenge.md#qualify-independently-recorded-effects).
- Qualify the Ground Truth Vehicle Safety Shield against a fleet of 1,024
  simulated vehicles. The offline campaign checks ledger mutations, local
  emergency braking during outages and oracle detection of deliberately defective
  controls. [GT-VSA architecture and reproduction](docs/gt-vsa.md).

---

## Research engine and detailed qualification

**Adversarial authorization experiments + an offline CI attack-path inspector.**
Run it against your *own* checked-out repository to review risky GitHub Actions
and container-build trust boundaries; get explainable JSON, Markdown, SARIF and
tamper-evident report hashes without executing the scanned project. The Stage 4
detection adds cross-workflow artifact-path correlation and a 39-case
differential mutation corpus. [Quick start](#stage-4-cross-workflow-attack-path-correlation).

**Stage 5:** the offline *evasion challenge* generates 128
independently labelled synthetic workflow pairs, probes the detector for
missed or downgraded trust paths, and saves every YAML case plus SHA-256
evidence. It never attacks a real repository or runs target code.
[Try the challenge](#stage-5-the-offline-evasion-tournament).

**Stage 5.1:** a separate offline, bounded agent-code recognizer emits three
conditional JavaScript/TypeScript review signals. Its independently labelled
108-case corpus supports saved-input replay and evidence verification.
The scanner does not interpret arbitrary agent framework semantics or establish
effective deployment and authority. [Agent inspection details](docs/agent-inspection.md).

**Stage 5.2:** a separately invoked, lexical protected-effect reviewer emits
13 *conditional* patterns learned from authorized read-only reviews of an
agent harness, a browser BYOK demo, and an agent skill library. It also fixes
the CI scanner's repeated mutable `uses:` action attribution by locating the
actual YAML step in each job. Neither feature expands Stage 5.1's syntax
contract or silently enables an automated block. [Details](docs/effect-inspection.md).

**Stage 5.3:** a separately invoked document scanner preserves the earlier
scanner grammars, supports long UTF-8 prompt collections within fixed caps,
and tests obfuscated instruction-disclosure attempts alongside benign excerpts.
The controls are author-created synthetic cases, not an independent hostile
review or real-world detection-rate measurement.

The original WolfTrap v0.1 is a bounded, standard-library Python research harness for testing authorization controls against synthetic systems. It translates defensive lessons from FBI `FLASH-20261113-001` into deterministic experiments. The synthetic authorization harness does not contact, exploit, or deploy to external systems; the optional local build inspector is a separate, later capability.

This repository is a security-engineering instrument, not an intrusion platform. Its deliberately defective systems are local test sentinels; a finding against one is not evidence of a real-world vulnerability. FBI and MITRE references provide threat provenance and taxonomy, not endorsement.

## What the engine verifies

WolfTrap schedules protected operations through explicit logical phases so that revocation, replay, crashes, recovery, and competing agents can be interleaved without relying on thread timing or wall clocks. A separately implemented reference-state oracle evaluates the actual append-only synthetic effect ledger. It does not accept a system-under-test response as proof that an effect did or did not occur.

The qualification invariants are:

- no current authority means no protected effect;
- no valid origin binding means no protected effect;
- revoked authority means no new protected effect;
- replayed authorization means no duplicate effect;
- verified does not mean authorized;
- authorized does not mean executed; and
- an unknown security state fails closed.

A legitimate positive control must also commit exactly one expected effect. Consequently, an implementation that denies everything cannot qualify.

The corpus has one positive baseline, seven strict negative baselines that must
produce no effect, and three mixed stateful threat baselines containing both
legitimate and rejected transitions. Reports account for these groups separately
and require all ten threat baselines to pass.

The bounded stateful explorer varies principals, scopes, authorization epochs, operation digests and arguments, execution order, concurrent requests, revocation timing, crash sites, retries, and recovery. Complete generated cases and schedules are evidence artifacts; a seed is not treated as a substitute for the saved case. Potential counterexamples are minimized on fresh fixtures and must reproduce independently before they can be classified `CONFIRMED`.

## Safety boundary

- All principals, credentials, resources, origins, destinations, effects, and defects are synthetic.
- Protected resources use the `synthetic://` namespace; transfer destinations use `synthetic-sink://`.
- The runtime accepts no hostname, target URL, shell command, payload, production credential, or arbitrary callable.
- The engine requires no Docker service, physical device, commercial system, paid API, or external target.
- OpenAI integration is disabled. No API key is read and no model call is required.
- The manual GitHub workflow has read-only repository permission. It neither deploys nor opens, merges, or modifies pull requests.

The optional defensive-hypothesis interface is intentionally separate from experiments and findings. The requested GPT-5.6 Sol with Daybreak Blue capability was not available during v0.1 construction, so it was not substituted with another model or represented as used. A future model proposal would remain `PROPOSED` until translated into a bounded deterministic test and independently verified by the same oracle and reproduction process.

## Local use

Python 3.11 or newer is required; Python 3.12 is used by the workflow. No runtime package dependencies are required.

```bash
export PYTHONPATH=src
python -m wolftrap.test_runner --output reports/unit-tests.json
python -m wolftrap run --seed 20261113 --max-mutations 32 --output-dir reports \
  --unit-test-summary reports/unit-tests.json --sut correct-v1
```

The runner writes canonical JSON evidence, a Markdown rendering, and a completion
manifest containing both artifact hashes. The pair is authoritative only when
the manifest state is `COMPLETE`; reproduction validates it before loading a
finding. Use the saved report and finding identifier to replay the exact
minimized case:

```bash
python -m wolftrap reproduce --report reports/wolftrap-report.json \
  --finding-id WOLFTRAP-F-0123456789ABCDEF0123 --output-dir reports/reproduction
```

Run `python -m wolftrap --help` for the implemented bounds and command names. Exit status `0` means the bounded qualification completed without a verified violation and all required controls passed; `1` means a finding or qualification-control failure occurred; `2` means schema, infrastructure, execution, or evidence state was unknown and the run stopped safely. A bounded result is never an exhaustive proof.

A qualifying campaign requires a mutation budget of at least 32 and at least one
depth-2 interaction. The default `32` / `8` bounds also require the complete
11-scenario corpus, all ten mutation axes, selected replay/revocation/recovery
race windows, and both positive and negative controls. `--scenario` is a targeted
diagnostic mode; it intentionally returns a non-qualifying result because it does
not exercise the complete gate.

The GitHub Actions workflow automatically runs a bounded Stage 2 qualification on pushes to the exact `feat/wolftrap-autonomous-stage2-v0_2` branch. It also supports manual dispatch using a validated seed. Each run executes the unit suite and the same fixed three-seed, 128-mutation, 55-pairs-per-seed synthetic qualification, verifies the aggregate completion manifest, and retains the evidence as a GitHub Actions artifact for 14 days even if qualification fails. There are no scheduled, pull-request, external-target, model, or paid-API triggers.

## Evidence and provenance

Each finding in the core synthetic research report records source and ATT&CK
references, exact commit and tree, dirty state, seed and full case, expected and
observed behavior, pre/post ledger evidence, minimization and reproduction
attempts, severity, confidence, and classification. Scanner and challenge
schemas have their own fields and limits. Model-generated hypotheses cannot
set a finding classification.

The authoritative threat input is:

- Federal Bureau of Investigation, `FBI FLASH-20261113-001`, November 13, 2026
- <https://www.ic3.gov/CSA/2026/261113.pdf>
- SHA-256 `3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2`

See [the source mapping](docs/threat-mapping.md) and its machine-validated
[complete advisory technique inventory](src/wolftrap/data/advisory-techniques-v1.json)
for the behavior-to-experiment trace. See [the research status](docs/research-status.md)
for lifecycle claim definitions. Generated reports are the authority for the exact
tested revision and actual counts.

## Non-goals

WolfTrap v0.1 does not perform external penetration testing, reproduce an intrusion campaign, provide offensive payloads, validate a live product, or expand into HERCULES, Ground Truth, MobiPute, financial systems, blockchain effects, or deployment. Owner authority remains with Stackbleed — Governable Intelligence.

## Stage 2: autonomous synthetic frontier

Stage 2 adds an unattended, bounded multi-seed sweep over all **55/55**
pairwise compositions of the existing 11 synthetic scenario families. Each seed
retains its complete case schedules, findings, JSON/Markdown reports, and
completion manifests. A stage-2 aggregate manifest is marked `COMPLETE` only
after its summary and constituent reports have been written. A single failing
control, missing unit-test attestation, truncated pair frontier, source change,
or infrastructure error prevents a `PASS`.

```bash
export PYTHONPATH=src
python -m wolftrap.test_runner --output reports/unit-tests.json
python -m wolftrap sweep --seed 20261113 --seed-count 3 \
  --mutation-budget 128 --unit-test-summary reports/unit-tests.json \
  --output-dir reports/stage2
```

Each seed runs with the same explicit bound of 55 interaction pairs, plus a
bounded mutation and schedule frontier. A `PASS` proves only this finite
synthetic qualification, not the correctness of an external system or an
exhaustive security analysis. A finding against a deliberately defective
sentinel is not a real-world vulnerability.

**No model integration has been enabled in Stage 2.** The optional GPT-5.6 Sol
/ Daybreak Blue hypothesis boundary remains disabled. Stage 2 reads no API
key, sends no network request, spends no credits, and exposes no external
target. A future model suggestion will have to become a schema-valid,
bounded deterministic case before the independent oracle can classify it.

## Stage 3: scan your own build, offline

WolfTrap Stage 3 adds a read-only local configuration inspector. It identifies
*conditional* GitHub Actions trust-boundary chains and Dockerfile supply-chain
signals, then produces JSON, Markdown, SARIF 2.1.0, and a SHA-256 evidence
manifest. Counterfactual explanations list the factors that would need to
change to break each composite detection. It does not execute inspected code.

Install the optional YAML parser in the environment running the scanner:

    python -m pip install -e '.[build-scan]'

Inspect your own local project and write results **outside** that project:

    wolftrap scan-build --root /path/to/my-project --output-dir /path/to/new-evidence

The root must be a local directory; URLs and network targets are unsupported.
Only top-level Dockerfile/Containerfile and GitHub Actions workflows are read,
with strict file-count and byte bounds. No secrets, source lines, subprocesses,
model calls, network calls, deployment, or credential use are required. The
scanner currently supports a finite rule set; it is not a general-purpose code
scanner, container image vulnerability scanner, or a certificate of security.

Exit status `0` means no supported pattern matched; `1` means human review is
required; `2` means incomplete/unsupported input and never implies safety.
Reports use `REVIEW_REQUIRED`, **not CONFIRMED EXPLOIT**. SARIF can be ingested
by compatible code-scanning tools under a separately authorized workflow.
See [Stage 3 build inspection](docs/build-inspection.md) for threat scope,
counterfactuals, usage, and interpretation.

The separate Stage 3 GitHub Actions qualification is limited to the
`feat/wolftrap-stage3-build-inspector-v0_3` branch and manual dispatch. It
installs a pinned YAML parser, runs the tests, scans only this repository's
build configuration and a deliberately flawed synthetic fixture, verifies
report hashes and expected findings, and retains evidence for 14 days. It
does **not** scan outside repositories, execute inspected target code, or
prove that a real-world build is exploitable.

## Stage 4: cross-workflow attack-path correlation

Stage 4 follows a *possible* supply-chain path across multiple GitHub Actions
files: an untrusted pull-request build produces an artifact, and a
`workflow_run` consumer with a write-capable token retrieves that **same
artifact from the triggering run**. Rule `WT-GHA-006` traces both workflow
files, links an artifact name by its SHA-256 digest, and increases the review
priority if it sees direct script execution from the downloaded directory.

This is more specific than a broad warning about privileged artifact use;
it does not infer missing permissions or claim a proven exploit. The packaged
39-case synthetic mutation corpus includes safe, concerning, and ambiguous
handoffs; ambiguous inputs fail **INCONCLUSIVE**. All targets remain local,
bounded, read-only and unexecuted.

**Try it on your own checked-out project:**

```bash
python -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/project --output-dir /path/to/new-evidence
```

The same command reports both existing Stage 3 rules and new Stage 4 traces
in JSON, Markdown and SARIF with a hash manifest. For a guaranteed positive
demo, scan `tests/fixtures/stage4_demo`; its workflows are deliberately
flawed **test data** and are not active GitHub Actions. See
[the Stage 4 path model and limitations](docs/build-inspection.md#stage-4-additive-model-cross-workflow-artifact-paths).

The independent Stage 4 workflow is branch-only/manual, uses read-only GitHub
permissions and uploads its local qualification evidence. It never runs code
from a scanned external repository. CodeQL, OpenSSF Scorecard, OSV-Scanner and
other mature tools remain complementary; WolfTrap does not claim to replace
them or to perform live penetration testing.

## Stage 5: the offline evasion tournament

Challenge WolfTrap's **own static detector** before asking it to review a
project. The tournament generates 128 synthetic workflow pairs divided equally
among direct script execution (`HIGH`), artifact-only handoff (`MEDIUM`),
broken trust links (`NONE`) and ambiguous linkage (`INCONCLUSIVE`).

The additional variants cover common execution wrappers such as
`bash -e`, `python3 -B`, `node --trace-warnings` and `env bash`, plus
noise steps, paths, artifact names and token/trigger changes. An independent
generator labels each case; those labels do **not** come from scanner output.
A deliberately crippled detector must fail the challenge's positive controls.

```bash
python -m pip install -e '.[build-scan]'
wolftrap challenge-build --seed 20261115 --cases 128 \
  --output-dir /path/to/new-challenge-evidence
wolftrap verify-challenge --evidence-dir /path/to/new-challenge-evidence
```

The report, Markdown scoreboard, and complete generated YAML cases have a
completion manifest with SHA-256 and byte counts. `PASSED_BOUNDED` (exit 0)
means only that this finite challenge matched all its synthetic expectations.
`DETECTOR_GAPS` (exit 1) means at least one mismatch. Invalid, incomplete, or
corrupt evidence fails closed (exit 2). Count must be a multiple of four from
64 to 256; seed is an unsigned 32-bit integer. Inputs and output are local.

Running `scan-build` on somebody else's checkout remains **read-only triage**;
it is never an authorization to execute that code, scan live hosts, or claim
a confirmed exploit. See [Stage 5 scope and replay](docs/evasion-challenge.md).
