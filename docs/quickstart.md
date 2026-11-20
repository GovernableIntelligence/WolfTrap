# WolfTrap — quick start for repository maintainers

WolfTrap helps you review local GitHub Actions, root container-build trust
boundaries, selected JavaScript/TypeScript agent trust boundaries, Stage 5.2
protected-effect and skill instruction patterns, and selected Go authority
source patterns. It does
**not** execute your application, run a pentest against a host, validate
deployment credentials, or guarantee that a repository is secure.

## Choose your path

For a free local wheel with no required runtime dependency, use the offline
candidate guide. It includes a fictional first scan, coverage explanations,
tamper detection and uninstall instructions. [Offline product quick start](offline-product.md).

### 1. Local command line (public beta)

Requirements: Python 3.11+, Git, a checked-out repository you are authorized
to inspect, and the optional YAML parser.

```bash
git clone https://github.com/GovernableIntelligence/WolfTrap.git
cd WolfTrap
python3 -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/my-repo --output-dir /tmp/wolftrap-my-repo
```

The target must be a local path. Use an initially empty output directory
outside the target. WolfTrap only inspects supported GitHub Actions workflow
files and root `Dockerfile`/`Containerfile`, subject to strict limits.

### 2. GitHub Action (public beta)

Copy [the reference workflow](../examples/wolftrap-scan.yml) into your own
repository at `.github/workflows/wolftrap.yml`. The example pins the Action
to the complete, hosted-qualified commit SHA
`4d1f075dadf257375a0ea59d39dea9151d07e3f5`. That immutable reference
does not automatically follow `main`; review and update it deliberately when
adopting future versions.

The Action defaults to **advisory** mode:

| Outcome | Meaning | CI default |
| --- | --- | --- |
| `NO_PATTERN_MATCH` | No supported pattern matched the inspected inputs | Success, **not** security PASS |
| `REVIEW_REQUIRED` | One or more conditional static findings | Success, evidence to review |
| `INCONCLUSIVE` | Incomplete, unsupported, missing, or corrupt input | Failure, never a clean result |

Set `fail-on-findings: 'true'` to fail CI on `REVIEW_REQUIRED` as well. It
does not change scanning behavior or grant additional authority.

The Action exposes `status`, `findings`, `unknown-inputs` and `evidence-dir`
step outputs, and retains evidence for 14 days by default. The uploaded
artifact contains the scanner-owned JSON, Markdown, SARIF, SHA-256 manifest,
and small action-status summary. It does **not** include your source code.

The GitHub runner downloads vetted pinned actions and installs PyYAML from
the package registry. **The scanner itself** does not make network requests
or execute the checked-out project. No GitHub token write access, secret,
model credential, or hosted external target is needed.

### 3. Challenge WolfTrap with synthetic adversarial cases

```bash
wolftrap challenge-build --seed 20261115 --cases 128 --output-dir /tmp/wt-challenge
wolftrap verify-challenge --evidence-dir /tmp/wt-challenge
```

The 128 saved synthetics cover 32 high-priority script paths, 32 artifact-only
handoffs, 32 broken links and 32 ambiguous paths. Matching all 128 is a finite
synthetic regression result; it is **not** an external exploit detection rate.

### 4. Offline agent source review (Stage 5.1)

This is a separate local inspection command, not an extension of the
community Action's CI/build checks. It uses the Python standard library and
does not need a model, API key, Node.js runtime, or network connection.

```bash
wolftrap scan-agent --root /path/to/your-agent-source \
  --output-dir /tmp/wolftrap-agent-review
```

Use a fresh, empty output directory outside the target. For explicit
selection, repeat `--file relative/path.ts` as needed. The scanner supports
bounded JavaScript/TypeScript lexical patterns for fail-open moderation
(`WT-AGENT-001`), unconditional authentication/approval
(`WT-AGENT-002`), and recognizable browser-visible credential logging
(`WT-AGENT-003`). All matches require manual review, including named mock
callbacks. Unrelated demo/mock comments cannot downgrade an authentication
finding. Unknown syntax, path ambiguity, or incomplete inspection is
`INCONCLUSIVE`, never an all-clear.

To challenge the detector using only saved, synthetic fixtures:

```bash
wolftrap challenge-agent --seed 20261115 --output-dir /tmp/wt-agent-cases
wolftrap verify-agent-challenge --evidence-dir /tmp/wt-agent-cases
wolftrap replay-agent-challenge --evidence-dir /tmp/wt-agent-cases \
  --output-dir /tmp/wt-agent-replay
wolftrap verify-agent-challenge --evidence-dir /tmp/wt-agent-replay
```

The 108-case corpus and replay demonstrate finite, local detection behavior;
they cannot certify another agent's runtime identity, authority, or safety.
Read [supported syntax, evidence, and limits](agent-inspection.md).

### 5. Offline protected-effect and skill scan (Stage 5.2)

This independent command reviews bounded JS/TS, Python, shell, and `SKILL.md`
inputs, looking for conditional unrestricted agent launch, host credentials,
explicit bypass, broad root mounts, browser API keys, upload instructions,
external destinations, and resource bounds.

```bash
wolftrap scan-effects --root /path/to/your-agent-source \
  --output-dir /tmp/wt-effects
wolftrap verify-effects --evidence-dir /tmp/wt-effects
```

Use repeated `--file relative/path.ts` and `--file skills/SKILL.md` for exact
selection. The command never executes inspected code. Rules require manual
review; a skill's claimed permission or approval cannot grant host authority.
All outputs are anonymous path aliases with JSON/Markdown/SARIF and SHA-256
evidence manifest. This is **not** part of the published CI/build Action's
automatic checks. See [the 13 conditional rule scopes](effect-inspection.md).

### 6. Offline Go authority-source review

This local-only mode recognizes four bounded permission, inherited-environment
process, proxy-transport and optional gate patterns in `.go` files:

```bash
wolftrap scan-go-authority --root /path/to/authorized-repo \
  --file server/tool.go --file guard/hooks.go \
  --output-dir /tmp/wt-go-review
wolftrap verify-go-authority --evidence-dir /tmp/wt-go-review
```

No Go toolchain, target execution or network access is needed. A reported
pattern requires independent authorization and effect-path analysis; no match
is not a pass. Details: [Go source scope and rules](go-authority-inspection.md).

## Interpret the results

- Open `build-scan.md` for recommendations and cited conditions.
- Use `build-scan.json` for structured downstream review.
- Use `build-scan.sarif` in compatible scanning/report tools, without granting
  WolfTrap a security-events write token by default.
- Verify `build-scan.manifest.json` SHA-256 hashes when retaining the report.
  Hashes are unsigned integrity checks, **not** proof of a trusted publisher.
- Treat HIGH and MEDIUM as **review priorities**, not confirmed exploits.
- `WT-GHA-007` flags explicit self-hosted runner labels in PR-triggered jobs.
  Custom labels or runner groups without that label cannot be reliably
  attributed from workflow text; `NO_PATTERN_MATCH` does not establish
  runner isolation or guarantee repo safety.
- Agent results are stored separately as `agent-scan.json`,
  `agent-scan.md`, `agent-scan.sarif`, and
  `agent-scan.manifest.json`; they do not change the CI/build rule count.

## What it does not do

It is not a general-purpose JavaScript parser, generic SAST engine, dependency
CVE scanner, SBOM generator,
container image scanner, live penetration-testing platform, fuzzing engine
for arbitrary services, or replacement for CodeQL/OSV-Scanner/OpenSSF.
Unknown workflow constructs or missing permission semantics may be outside
its model; absence of findings is not evidence of absence of risk.

Only scan repositories you own or are authorized to examine. For confirmed
upstream defects, use the owner's responsible-disclosure process.
