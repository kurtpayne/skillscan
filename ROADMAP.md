# SkillScan Roadmap

> **Last updated:** 2026-03-22
> **Version:** 0.3.2
>
> SkillScan was designed and directed by Kurt Payne and built with [Manus](https://manus.im).

---

## Product Direction

SkillScan is an **offline, privacy-first security scanner for AI agent skill files**. It ships as a CLI, a Docker image, and editor extensions. It runs entirely on the developer's machine — no network calls, no telemetry, no API keys required.

The two user-facing products are:

- **`skillscan`** — security scanner. Detects malicious intent, prompt injection, exfiltration channels, supply chain risks, and social engineering in SKILL.md files. Eight detection layers: static rules, chain rules, AST data-flow analysis, ML classifier, IOC/vuln DB, semantic classifier, skill graph, and permission scope validation.
- **`skillscan-lint`** — quality linter. Checks SKILL.md files for LLM-effectiveness issues: missing front-matter, ambiguous instructions, over-broad tool declarations, and schema violations.

These two tools are the product. The behavioral tracer (`skillscan-trace`) and training corpus (`skillscan-corpus`) are private infrastructure that improve the ML model and validate detection rules. They do not ship to users and are not part of the public roadmap.

**SaaS scanner** (token-gated hosted scanning with permanent report URLs) is a future phase. It is not on the active roadmap. The prerequisite is a false positive rate below 2% on benign skills and a detection rate above 85% on the malicious corpus. The current ML model (v7458, macro F1 0.8448, FPR 15.7%) does not yet meet that bar. The SaaS design is documented in `skillscan-trace/ROADMAP.md` Phase 3 for reference when the time comes.

---

## Current State (2026-03-22)

### What is working and shipped

| Component | Status | Notes |
|---|---|---|
| Static rules | **117 rules** (85 static + 15 chain + 17 multilang) | `default.yaml`, `multilang.yaml` |
| AST data-flow analysis | **Complete** | `detectors/ast_flows.py` — secret→decode→exec/network flows |
| Skill graph / PSV | **Complete** | `detectors/skill_graph.py` — PSV-001/002/003 permission scope validation |
| ML classifier | **v7458, macro F1 0.8448** | DeBERTa-v3-base + LoRA, ONNX INT8, HuggingFace Hub |
| IOC DB | **2,051 entries** (bundled) | 503 domains, 17 IPs, 1,527 CIDRs, 4 URLs; runtime feeds via `managed_sources.json` |
| Vuln DB | **35 packages** | 26 Python + 9 npm |
| Semantic classifier | **Complete** | `semantic_local.py` — offline stem-and-score, no network |
| `skillscan diff` | **Complete** | Instruction-level diff with security-relevant change flagging |
| SARIF / JUnit / CycloneDX output | **Complete** | CI-ready output formats |
| Docker image | **Complete** | Multi-arch, published to Docker Hub |
| GitHub Actions integration | **Complete** | `integrations/github-actions/` |
| VS Code extension | **Scaffolded, not published** | Blocked by Microsoft account registration issue |
| `skillscan-lint` | **Complete** | SARIF output, schema validation, front-matter checks |
| Skill fuzzer | **Complete** | `tools/skill-fuzzer/` — 5 mutation strategies, evasion rate reporting |
| Test suite | **300 test functions** across 30 files | |
| Showcase examples | **104 examples** covering all rule categories | |

### ML model state

The v7458 fine-tune (2026-03-22) is the first run to pass the F1 gate:

| Metric | v1278 (previous) | v7458 (current) | Target (v0.4.0) | Target (v1.0) |
|---|---|---|---|---|
| Training corpus | ~210 examples | **7,277 examples** | 10,000+ | 20,000+ |
| Macro F1 | 0.7544 (FAILED) | **0.8448** (PASSED) | ≥ 0.90 | ≥ 0.93 |
| Benign F1 | 0.8421 | 0.9040 | ≥ 0.90 | ≥ 0.93 |
| Injection F1 | 0.6667 | **0.7857** | ≥ 0.85 | ≥ 0.90 |
| FPR | 18.4% | **15.7%** | ≤ 12% | ≤ 5% |

The injection recall improvement (+0.119) is the main story. The 12 injection eval examples still scoring 0.0 are all obfuscation-style variants — these are the highest-priority corpus additions for the next fine-tune.

### Open gaps

| Gap | Severity | Milestone |
|---|---|---|
| ML injection recall on obfuscation variants | **High** | M7 |
| FPR at 15.7% (target ≤ 10% for SaaS) | **High** | M7 |
| `docs/MODEL_METRICS.md` stale (shows v1278) | **Medium** | M10 |
| Chain rule proximity window missing | **Medium** | M6 |
| PSV rules not wired through rule YAML | **Medium** | M8 |
| Vuln DB thin (35 packages) | **Medium** | M5 |
| IOC DB bundled only 2,051 entries | **Medium** | M5 |
| VS Code extension unpublished | **Low** | M9 |
| `exfil_channels.yaml` not merged into `default.yaml` | **Low** | M6 |
| `docs/RELEASE_ONBOARDING.md` stale | **Low** | M10 |
| `docs/PROMPT_INJECTION_CORPUS.md` references non-existent script | **Low** | M10 |
| No warning when ML model is not installed | **Low** | M10.5 |

---

## Design Principle: The Static Analysis Ceiling

Static offline analysis has a hard ceiling. Almost all of the highest-value gaps — runtime behavior prediction, indirect injection from external content fetched at runtime, temporal and conditional payloads, MCP server infrastructure trust — require dynamic execution or infrastructure-level signals. These are not gaps we can close with better regex or a larger corpus.

**This is a feature, not a limitation.** The offline/private/deterministic positioning is the reason teams trust SkillScan in security-sensitive environments. We own the offline trust layer completely and are honest about where dynamic analysis begins.

The one exception is `skillscan-trace` (private): a local execution harness that runs a skill through an instrumented agent environment. The user supplies model credentials; we supply the canary environment and detection layer. This stays within the offline/private paradigm and remains private infrastructure.

---

## Milestone 5 — Intel & Vuln DB Depth *(next up)*

**Goal:** Make the IOC and vuln DBs credible enough that a security team trusts them.

The bundled IOC DB has 2,051 entries. The runtime feed integration works but is not tested in CI. The vuln DB has 35 packages — thin for a tool claiming supply chain coverage.

**IOC DB actions:**
- Expand the bundled IOC DB to 5,000+ entries by seeding from Abuse.ch URLhaus (hosts only), Feodo Tracker, and Spamhaus DROP/EDROP. The `intel_update.py` script already supports these sources.
- Add at least 10 hand-curated campaign IOCs from recent MCP-related threat intel (the 2026-03-21 PATTERN_UPDATES.md entries are candidates).
- Add a CI test validating bundled DB has ≥ 5,000 entries and all entries parse correctly.

**Vuln DB actions:**
- Add the top 15 most-referenced Python packages from the GitHub skills corpus that have known CVEs: `requests`, `urllib3`, `cryptography`, `paramiko`, `pillow`, `aiohttp`, `httpx`, `boto3`, `sqlalchemy`, `django`, `flask`, `fastapi`, `celery`, `redis`, `pymongo`.
- Add the top 10 npm packages: `axios`, `express`, `node-fetch`, `got`, `superagent`, `ws`, `socket.io`, `jsonwebtoken`, `bcrypt`, `multer`.
- Source from OSV.dev API (already integrated in `intel_update.py`).

**Acceptance criteria:** Bundled IOC DB ≥ 5,000 entries. Vuln DB ≥ 50 packages. CI gate validates both counts. No regression in false positive rate on the benign showcase examples.

---

## Milestone 6 — Chain Rule Precision

**Goal:** Reduce false positives from chain rules on large, legitimate SKILL.md files.

The current chain rules (CHN-001 through CHN-014) match patterns anywhere in the document. A 2,000-line SKILL.md that mentions both "read credentials" and "http request" in unrelated sections will trigger CHN-001 even if the two patterns are 1,500 lines apart. The fix is a proximity window.

**Actions:**
- Add a `window_lines` field to chain rule definitions in `default.yaml`. Default: `null` (current whole-document behavior). Set `window_lines: 40` on CHN-001, CHN-002, CHN-004, CHN-005 as the highest false-positive rules.
- Update `rules.py` to enforce the window when `window_lines` is set.
- Add metadata blocks to all 15 chain rules (currently only static rules have metadata guards).
- Migrate `exfil_channels.yaml` (EXF-002, CHN-003) into `default.yaml` and delete the satellite file.

**Acceptance criteria:** CHN-001/002/004/005 false positive rate on the 104 benign showcase examples drops to zero. All chain rules have metadata blocks. `exfil_channels.yaml` is deleted.

---

## Milestone 7 — ML Model Quality: Injection Recall

**Goal:** Push injection F1 from 0.7857 to ≥ 0.85, closing the gap on obfuscation-style attacks.

The 12 injection eval examples still scoring 0.0 are all obfuscation or indirect-style attacks. The model has not seen enough training examples of this pattern.

**Actions:**
- Add 50+ training examples covering the 12 failing eval patterns: markdown injection, LaTeX injection, tool name spoofing, exfil via error messages, fake changelogs, conditional triggers, supply chain dependency injection, webhook exfil logging, author field injection, RSS indirect injection, prompt leak via translation, context flooding.
- Run back-translation augmentation (`scripts/backtranslate_augment.py`, already written) on the 12 failing examples to generate 4–5 natural English variants each.
- Trigger a new fine-tune. Target: injection F1 ≥ 0.85, FPR ≤ 12%.
- Update `docs/MODEL_METRICS.md` with v7458 results and the new run results.

**Acceptance criteria:** Injection F1 ≥ 0.85 on the 181-example held-out eval set. FPR ≤ 12%. `MODEL_METRICS.md` is current.

---

## Milestone 8 — Skill Graph / PSV Rule Wiring

**Goal:** Make PSV rules first-class citizens surfaced through the standard rule YAML path.

PSV-001/002/003 are implemented in `detectors/skill_graph.py` but have no entries in `default.yaml`. This means they do not appear in `skillscan rule list` output and cannot be suppressed via `--suppress-rule`.

**Actions:**
- Add PSV-001, PSV-002, PSV-003 stubs to `default.yaml` with full metadata (description, severity, references, techniques).
- Ensure `skillscan rule list` shows PSV rules.
- Ensure PSV findings can be suppressed via `--suppress-rule PSV-001`.
- Add 5 showcase examples for PSV rules.

**Acceptance criteria:** `skillscan rule list` shows PSV-001/002/003. PSV findings appear in SARIF output. Suppression works. 5 new showcase examples pass.

---

## Milestone 9 — Editor Extensions: Zed and JetBrains

**Goal:** Publish working editor extensions for Zed and JetBrains IDEs.

The VS Code extension is scaffolded but blocked by Microsoft's account registration process. Zed and JetBrains are the active targets. Both support LSP-based diagnostics — the extension is a thin wrapper that runs `skillscan --format sarif` and maps findings to editor diagnostics.

**Actions:**
- Implement Zed extension using Zed's extension API (Rust-based, published to the Zed extension registry).
- Implement JetBrains plugin using the IntelliJ Platform SDK (Kotlin, published to JetBrains Marketplace).
- Both extensions surface `skillscan` and `skillscan-lint` findings as inline diagnostics with severity levels.
- Add installation instructions to `docs/DISTRIBUTION.md`.

**Acceptance criteria:** Both extensions installable from their respective registries. Findings appear inline in the editor. At least one screenshot in the README.

---

## Milestone 10 — Documentation Accuracy

**Goal:** Ensure all docs reflect current state. No stale metrics, no references to non-existent files.

**Actions:**
- Update `docs/MODEL_METRICS.md` with v7458 results and the full comparison table.
- Update `docs/DETECTION_MODEL.md` Layer 7 (ML) with current model architecture and performance.
- Add a "What SkillScan does not detect" section to `docs/DETECTION_MODEL.md`.
- Condense `docs/RELEASE_ONBOARDING.md` into `docs/RELEASE_CHECKLIST.md` and delete it.
- Resolve the `docs/PROMPT_INJECTION_CORPUS.md` reference to a non-existent script (delete or fix).

**Acceptance criteria:** All docs reflect current state. No references to non-existent files or scripts. `skillscan --version` output matches `pyproject.toml`.

---

## Milestone 10.5 — Model UX: Missing-Model Detection & Guided Download

**Goal:** Give users a clear, actionable error when the ML model is not installed, instead of a silent failure or cryptic traceback.

Currently, if a user runs `skillscan` without having run `skillscan model sync`, the ML detector silently falls back to rule-only mode with no indication that the model layer is inactive. Users have no way to know they are getting reduced injection recall.

**Actions:**
- In `ml_detector.py`, detect the missing-model case at startup and emit a structured warning: `[WARN] ML model not installed — injection recall is reduced. Run: skillscan model sync`.
- In the CLI (`cli.py`), intercept the missing-model warning and offer an interactive prompt when running in a TTY: `ML model not found. Download now? [Y/n]`. If the user confirms, invoke `skillscan model sync` inline before proceeding with the scan.
- Add a `--no-model` flag to explicitly opt out of the model layer and suppress the warning (useful in CI environments where the model is intentionally excluded to save disk space).
- Add a `--require-model` flag that exits with a non-zero code if the model is not installed (useful for gating CI jobs on full-fidelity scans).
- Ensure `skillscan model sync` prints the model version, size, and a brief description of what it enables after a successful download.
- Add a test in `tests/test_ml_detector.py` that asserts the correct warning is emitted when the model directory is absent.

**Acceptance criteria:** Running `skillscan scan <path>` without a model installed prints the warning and offers the interactive download prompt (TTY only). `--no-model` suppresses the warning. `--require-model` exits non-zero when the model is absent. `skillscan model sync` output is informative.

---

## Milestone 10.6 — Organic Eval Pipeline & Corpus Commit Policy

**Goal:** Establish a closed feedback loop between the pattern update agent and the ML model, ensuring every new attack pattern discovered in the wild is immediately tested against the model and tracked as a known gap if missed.

**Background:** The pattern update skill discovers real-world threats on a schedule. Previously, new patterns were added directly to the training corpus, which contaminates the held-out eval set and makes F1 scores unreliable. The correct architecture:

1. New patterns land in `held_out_eval/organic/` in `kurtpayne/skillscan-corpus` (eval-only, never training data)
2. CI runs the held-out eval after each fine-tune, reporting hand-crafted vs organic breakdown
3. If the model misses an organic example (FN), a GitHub issue is opened automatically in `skillscan-security`
4. After a fine-tune that correctly classifies the example, it is *promoted* to the training corpus and removed from eval

**Status as of 2026-03-23:**
- ✅ `skillscan-pattern-update` skill updated to write organic eval examples to `held_out_eval/organic/` and commit to private corpus repo
- ✅ `corpus/` gitignored in `skillscan-security` — cannot be re-added accidentally
- ✅ Corpus commit policy documented: all training data lives in `kurtpayne/skillscan-corpus` (private)

**Remaining actions:**
- Create `held_out_eval/organic/` directory in `kurtpayne/skillscan-corpus` with a `README.md` explaining the promotion workflow.
- Create `PROMOTION_CANDIDATES.md` in `kurtpayne/skillscan-corpus` to track examples ready for promotion.
- Update `finetune_modal.py` to include `held_out_eval/organic/` in the held-out eval run and report per-source breakdown.
- Add a post-eval step in `finetune_modal.py`: if any organic example is a FN, open a GitHub issue in `skillscan-security` titled `[ML Regression] Model misses organic pattern: {pattern_id}`.

**Acceptance criteria:** Pattern update skill writes organic eval examples and commits. Post-eval step opens GitHub issues for FN organic examples. `PROMOTION_CANDIDATES.md` is maintained. `corpus/` cannot be re-added to the public repo.

---

## Milestone 10.7 — CLI UX Audit & Command Consolidation

**Goal:** Reduce user friction by consolidating fragmented sub-commands into a coherent, discoverable CLI surface.

**Problem statement:** The CLI has grown organically and now has multiple overlapping entry points for related operations:

- **Update fragmentation**: `skillscan update-rules`, `skillscan update-ioc`, `skillscan update-model`, and `skillscan-intel-daily-update` are four separate commands that users must know about and run independently. A user who runs `skillscan update` expects everything to be current.
- **Diff sub-command sprawl**: `skillscan diff` and `skillscan-lint diff` overlap in scope. The distinction between a security diff and a quality diff is not obvious to new users.
- **Model management opacity**: There is no single command that shows the user what version of the model is installed, whether it is current, and how to update it. `skillscan model` does not exist yet.
- **Inconsistent naming**: Some commands use hyphens (`update-rules`), others use underscores in the underlying Python, and the lint tool uses a separate binary name.

**Proposed consolidated surface:**

| New command | Replaces | Notes |
|---|---|---|
| `skillscan update` | `update-rules`, `update-ioc`, `update-model`, `skillscan-intel-daily-update` | Updates all components; `--rules`, `--ioc`, `--model` flags for selective updates |
| `skillscan model status` | *(missing)* | Shows installed version, HF Hub latest, and whether an update is available |
| `skillscan model sync` | *(missing)* | Downloads/updates the ML model with progress bar |
| `skillscan diff` | `skillscan diff` + `skillscan-lint diff` | Unified diff with `--security` / `--quality` / `--all` flags |
| `skillscan lint` | `skillscan-lint` | Alias; `skillscan-lint` binary remains for backward compat |

**Remaining actions:**
- [ ] Audit all CLI entry points and document current surface in `docs/CLI_REFERENCE.md`
- [ ] Design the consolidated command hierarchy (use Click groups)
- [ ] Implement `skillscan update` as a meta-command that runs all update sub-steps in order with a single progress display
- [ ] Implement `skillscan model status` and `skillscan model sync` (prerequisite: Milestone 10.5)
- [ ] Unify `skillscan diff` to accept `--security` and `--quality` flags
- [ ] Add `skillscan-lint` as an alias under the main `skillscan` group
- [ ] Update `--help` text, man page, and README to reflect the new surface
- [ ] Add deprecation warnings on old command names with migration hints
- [ ] Update GitHub Actions integration templates to use new commands

**Acceptance criteria:**
- A new user can run `skillscan update` and have rules, IOC DB, and model all current
- `skillscan --help` shows a coherent, scannable command list with no redundancy
- All old command names still work but print a deprecation hint pointing to the new name
- CI workflow uses only the new command surface

---

## Milestone 11 — Hardening & PyPI Publish

**Goal:** Ensure the scanner is robust enough for enterprise CI/CD use.

**Actions:**
- Audit and complete timeout and file-size guards across all detectors.
- Add a `--max-file-size` flag (default: 1MB) to skip oversized files with a warning.
- Add a `--timeout` flag (default: 30s per file) to prevent hangs on pathological inputs.
- Add release smoke tests: `pip install skillscan-security && skillscan --version` and `docker run skillscan:latest --version` on each tag, for Linux/macOS/Windows.
- Confirm PyPI publish under the `skillscan-security` name is current and working.

**Acceptance criteria:** Smoke tests pass on all three platforms. `--max-file-size` and `--timeout` flags work correctly.

---

## Milestone 12 — Binary Detection & Multi-Language Coverage ✅ Complete

Completed 2026-03-18. `multilang.yaml` covers JavaScript/TypeScript, Ruby, Go, and Rust with 17 static rules. Binary/encoded payload detection is included in `default.yaml` (OBF-001/002/003).

---

## Milestone 13 — Docs & Metadata Consolidation *(partially complete)*

Completed: `RELEASE_VERIFICATION_0.2.3.md` deleted, `PRD.md` (root) deleted, `AUTOMATION_GUARDRAILS.md` merged, `PLATFORM_SKILLS.md` merged, `docs/OPENCLAW_CONTEXT.md` IOC seeds updated, `docs/THREAT_MODEL.md` stale notes fixed.

Remaining items folded into Milestones 10 and 6:
- `docs/RELEASE_ONBOARDING.md` → condense into `RELEASE_CHECKLIST.md` (M10)
- `exfil_channels.yaml` → merge into `default.yaml` (M6)
- Chain rule metadata guard → extend to cover chain rules (M6)
- `docs/PROMPT_INJECTION_CORPUS.md` → resolve or delete (M10)

---

## Milestone 14 — Public Scan Feed

**Goal:** A daily-updated public feed of scanned skills on the SkillScan website, demonstrating real-world detection value.

This is the primary distribution mechanism for the offline product. A developer who sees a skill flagged on the public feed will install the scanner to check their own skills. The feed also builds the known-good registry needed for Milestone 17 (similarity hashing).

**Actions:**
- Daily cron job that scans the top 50 most-starred skills from the Claude skills registry and the OpenClaw index.
- Results stored as static JSON, rendered by the website's Feed page (already scaffolded).
- Each scan result shows: skill name, source URL, finding count by severity, top finding ID and description.
- A "scan this skill" button that links to the CLI install instructions.

**Acceptance criteria:** Feed updates daily. At least 50 skills shown. Results are accurate (no false positives on well-known benign skills). Feed page loads in < 2s.

---

## Milestone 15 — skillscan-core Extraction

**Goal:** Extract shared logic into a `skillscan-core` package that both `skillscan` and `skillscan-lint` depend on.

Currently the two tools share code via direct imports. As the tool family grows, this becomes a maintenance burden. Extracting a `skillscan-core` package with the shared graph model, front-matter parser, SKILL.md schema, fingerprinting, and diff engine is the right architectural move. This is a prerequisite for `skillscan-provenance`.

**Acceptance criteria:** `skillscan-core` published to PyPI. Both `skillscan` and `skillscan-lint` depend on it. No user-visible behavior change.

---

## Milestone 16 — Behavioral Diff & Suppression Integration *(partially complete)*

PSV-001/002/003 are implemented in `skill_graph.py`. `skillscan diff` is implemented in `skill_diff.py`. Remaining work:
- Wire PSV rules through the standard rule YAML path (now Milestone 8).
- Add suppression file integration to `skillscan diff` output.
- Add a `--baseline` flag to `skillscan diff` that reads a suppression file and only reports new findings.

---

## Milestone 17 — Instruction-Level Similarity Hashing

**Goal:** Detect skills that are near-copies of known-good skills with malicious additions.

A malicious skill that is 95% identical to a popular trusted skill but with one added exfiltration instruction is invisible to the current static rules. Instruction-level similarity hashing against a known-good registry would catch this.

**Implementation:** MinHash or SimHash over the instruction tokens. A similarity score above 0.85 against a known-good skill triggers a warning; above 0.95 with a finding in the diff triggers a high-severity alert.

**Prerequisite:** Milestone 14 (public scan feed) builds the known-good registry as a side effect.

---

## Deferred

**VS Code Marketplace publish.** The publisher registration process at marketplace.visualstudio.com requires a Microsoft account with working captcha/account recovery, which has been broken for an extended period. The extension code is maintained in `editors/vscode/` and can be installed locally. Revisit if Microsoft fixes the registration flow.

**SaaS control plane / multi-tenant API.** The hosted service design is documented in `skillscan-trace/ROADMAP.md` Phase 3. Prerequisites before this becomes active: FPR ≤ 2% on benign skills, detection rate ≥ 85% on the malicious corpus, skillscan-trace v1.0 complete. None of these prerequisites are met today. The SaaS design is sound — token packs, permanent report URLs, async scan queue, GitHub Action integration — but building it before the product quality bar is met would damage trust faster than any marketing can recover.

**Automatic code remediation.** Out of scope. The scanner's job is to surface findings, not rewrite code.

**Public signing and transparency log workflow.** The SBOM pipeline (CycloneDX + cosign) is already in place. Full Sigstore/Rekor integration can wait until the project has meaningful downstream consumers.

**Dynamic analysis beyond skillscan-trace.** Indirect prompt injection from external content fetched at runtime, temporal/conditional payload detection via symbolic execution, MCP server infrastructure trust validation, and compositional safety analysis across a live agent session are all real gaps. They require cloud execution, infrastructure-level signals, or LLM semantic reasoning that cannot be fully local. These are not on the roadmap for the static tools.

---

## Risks & Guardrails

**False positives from ML detection.** Guardrail: ML findings are advisory by default; threshold is 0.70; current FPR is 15.7%, acceptable for offline use but not for SaaS. Milestone 7 targets FPR ≤ 12%.

**Performance regressions from extra scanners.** Guardrail: strict budgets (timeout, bytes, files), benchmark gates in CI.

**Distribution drift / broken installs.** Guardrail: release smoke tests for `pip` and Docker on each tag (Milestone 11).

**Complexity creep.** Guardrail: keep features optional and policy-driven; preserve deterministic core.

**Thin intel data making the scanner look like a demo.** Guardrail: Milestone 5 is the highest-priority milestone. Do not ship v0.4.0 without credible IOC and vuln DB depth.

---

## Success Metrics

### Detection Quality

| Metric | Current (2026-03-22) | Target (v0.4.0) | Target (v1.0) |
|---|---|---|---|
| Static + chain rules | 117 (102 static + 15 chain) | 130+ | 150+ |
| ML corpus size (training) | 7,277 examples | 10,000+ | 20,000+ |
| ML macro F1 (held-out) | **0.8448** (v7458, gate PASSED) | ≥ 0.90 | ≥ 0.93 |
| ML injection F1 | 0.7857 | ≥ 0.85 | ≥ 0.90 |
| ML FPR | 15.7% | ≤ 12% | ≤ 5% |
| IOC DB entries (bundled) | 2,051 | 5,000+ | 20,000+ |
| Vuln DB packages | 35 | 50+ | 150+ |
| Showcase examples | 104 | 120+ | 150+ |

### Ecosystem Coverage

| Metric | Current | Target (v1.0) |
|---|---|---|
| VS Code extension | scaffolded, not published | published (pending Microsoft fix) |
| Zed extension | not started | published |
| JetBrains plugin | not started | published |
| SARIF / JUnit / CycloneDX output | complete | complete |
| skillscan-core package | not extracted | PyPI published |
| Skill fingerprinting | not implemented | complete (M17) |
| PSV rules in rule YAML | implemented in graph, not in YAML | wired (M8) |
| Instruction-level diff | complete | + suppression integration (M16) |
| Similarity hashing | not implemented | complete (M17) |
| Public scan feed | scaffolded | daily cron, 50+ skills (M14) |
| SaaS scanner | not started | post-v1.0, when quality bar met |

### Milestone Priority Order

| Priority | Milestone | Rationale |
|---|---|---|
| 1 | **M5 — Intel & Vuln DB Depth** | Makes the product credible to security teams |
| 2 | **M7 — ML Injection Recall** | Closes the last major quality gap; enables SaaS prerequisite |
| 3 | **M6 — Chain Rule Precision** | Reduces false positives; improves enterprise CI/CD trust |
| 4 | **M8 — Skill Graph / PSV Wiring** | Makes PSV rules first-class citizens |
| 5 | **M14 — Public Scan Feed** | Primary distribution mechanism; builds known-good registry |
| 6 | **M10 — Documentation Accuracy** | Required for enterprise evaluators |
| 7 | **M11 — Hardening & PyPI** | Required for enterprise CI/CD |
| 8 | **M9 — Editor Extensions** | Distribution; lower priority than product quality |
| 9 | **M15 — skillscan-core** | Architectural; not blocking any user feature |
| 10 | **M17 — Similarity Hashing** | Requires M14 (known-good registry) as prerequisite |
| — | **SaaS** | Post-v1.0; requires FPR ≤ 2%, detection ≥ 85% |

---

## Report Generation

### Overview

SkillScan can produce a structured enterprise security report combining static analysis output and dynamic trace data. The report is the primary commercial artifact — it is what an enterprise security team receives as the deliverable of a scan engagement.

Two canonical variants exist:

| Variant | When issued | Content |
|---|---|---|
| **PASS** | All checks pass, no findings | Clean bill of health, tool-surface adherence proof, 90-day approval, residual risk caveats |
| **BLOCK** | One or more findings | Per-finding detail with evidence, trace behavioral narrative, canary relay summary, remediation guidance |

Sample reports are stored in `skillscan-website/docs/sample-reports/` (private, not served by the website).

### Reproducibility

The report is compiled from three inputs:

1. `skillscan scan <dir> --output json` — static analysis JSON
2. `skillscan-trace <dir> --inputs 3 --output json` — dynamic trace JSON
3. An LLM compiler prompt that takes both JSONs and renders the Markdown report

The compiler prompt is the only component not yet built. Everything else is already implemented. Building the compiler is approximately a half-day task once the report format is finalized. The sample reports in `skillscan-website/docs/sample-reports/` are the canonical format specification.

### Value-add items identified (2026-03-22)

The following enhancements increase the report's credibility and utility for enterprise buyers. All are implementable with existing tooling.

**File integrity manifest (high priority).** Every file analyzed should be listed with its SHA-256 hash and the URL or path it was fetched from. For skills fetched from GitHub or a registry, the URL + commit SHA + file hash together constitute a tamper-evident provenance record. Implementation: add a `manifest` block to the scan JSON output (one entry per file: `{path, sha256, source_url, fetched_at}`). The report compiler includes this as an appendix table.

**Multi-model trace (high priority).** Run the dynamic trace against two or more models (e.g., claude-sonnet-4-5 + gpt-4.1) and report where they agree and diverge. A skill that behaves maliciously on one model but not another is a significant finding — it may indicate the skill was tuned to exploit a specific model's behavior. Agreement between models increases confidence in both PASS and BLOCK verdicts. The `skillscan-trace` harness already supports `--model`; the report compiler needs a multi-model comparison section and the runs can be parallelized.

**Confidence-weighted finding severity (medium priority).** Each static finding already has a `confidence` field (0.0–1.0). Surface this in the report as a visual indicator so the reader can distinguish a near-certain finding from a heuristic one. Especially important for semantic classifier findings, which are probabilistic by nature.

**Suppression audit trail (medium priority).** When a finding is suppressed, the report should include the suppression entry, the author, the date, and the documented rationale. This gives the customer an auditable record of what was reviewed and consciously accepted.

**Dependency vulnerability section (medium priority).** For skills that reference `pip install` or `npm install` commands, extract the package names and versions and cross-reference against the vuln DB. Surface any CVEs as a separate "Dependency Vulnerabilities" section. Natural complement to the existing supply chain detection rules.

**Delta / baseline comparison (lower priority).** If a previous scan report exists for the same skill, include a delta section: "3 new findings since last scan, 1 resolved." Creates recurring scan value — a customer who scans on every PR merge needs to know what changed. Prerequisite: `skillscan diff` (already implemented).

### Report structure (canonical)

1. Cover / executive summary — verdict, risk score table, scan metadata
2. Detection layers active — table: layer, type, findings count
3. Per-skill findings — static findings with evidence + dynamic trace narrative
4. IOC and domain analysis — table: domain, skill, IOC listed, trace observed
5. Methodology and limitations — honest caveats (required for enterprise credibility)
6. Remediation guidance — table: skill, priority, action
7. Appendix — scan configuration + file integrity manifest

### SaaS report delivery (future)

When the SaaS scanner is built, reports will be delivered as a signed PDF (tamper-evident, customer-specific watermark), a machine-readable JSON report (for SIEM/SOAR integration), and a SARIF file (for GitHub Advanced Security / Azure DevOps integration). The signing infrastructure and token system are out of scope until the offline product quality bar is met (FPR ≤ 2%, macro F1 ≥ 0.90).

---

## Product Wishlist (2026-03-22)

These items were identified during the report design session. They are not yet assigned to milestones. They are grouped by buyer persona — publisher, enterprise, and future SaaS — so the priority order can be set in context of which market segment is being served first.

### Publisher-facing features

**Publisher badge / attestation (highest ROI item on this list).** A scannable SVG badge that a publisher embeds in their skill's README or marketplace listing: "Scanned by SkillScan v0.3.1 — PASS — 2026-03-22 — report `a3f9b2c1`." The hash links to the full report. This is a direct commercial incentive for publishers to pay for scans — it is a trust signal they can display publicly. It also makes every badged skill README a distribution channel for SkillScan. Implementation: a small badge generator (SVG template + report hash) and a static registry of issued badges (JSON file in a private repo, or a simple lookup endpoint). The report already exists; the badge is the last 50 lines of code. Build this alongside the report compiler.

**Pre-commit / pre-publish scan hook.** A GitHub Action or CLI hook that runs the static scan on every commit and blocks the push if a Critical finding is present. Publishers want this because it catches mistakes before they become incidents. The static scanner already works as a CLI; the GitHub Action wrapper is approximately 50 lines of YAML. This is publisher-facing, self-serve, and should be free or very cheap — it drives adoption and surfaces the paid report tier when findings are found. Distinct from the enterprise CI integration (M11), which is buyer-facing.

**Regression alerts.** When a skill is re-scanned and a new finding appears that was not present in the previous scan, notify the publisher via email or webhook. "Your skill `onboarding-assistant` now triggers EXF-001 — this may have been introduced in the last commit." Publishers want to know when their skill regresses without having to remember to re-scan manually. Prerequisite: the delta/baseline comparison feature and a publisher account concept (even a simple email registration).

**Skill signing.** A publisher signs their SKILL.md with a keypair; the signature is embedded as front-matter. Enterprise buyers can verify the signature before loading the skill. SkillScan becomes the trust anchor — it issues a signed attestation that the skill passed at a specific version. This is a larger infrastructure investment (key management, revocation) and is a post-v1.0 item. Worth noting here because it is the natural endpoint of the publisher trust chain and informs the SaaS architecture.

### Enterprise buyer-facing features

**Policy profiles (high priority).** Right now there is a single `strict` profile. An enterprise should be able to define their own policy in a YAML file: "allow `http_fetch` to internal domains only," "require all skills to declare `allowed-tools`," "block any skill with a social engineering score above 0.7," "treat MEDIUM findings as WARN rather than BLOCK." The scanner already has all the underlying data (finding IDs, confidence scores, severity levels); a policy profile is a YAML mapping of finding IDs to PASS/WARN/BLOCK thresholds. This is a strong enterprise differentiator — it makes the tool configurable to the customer's risk tolerance rather than one-size-fits-all. Implementation: a `--policy` flag on `skillscan scan` that loads a policy YAML and overrides default severity thresholds.

**Bulk scan with summary dashboard.** An enterprise with 50 internal skills needs to scan all of them and see a summary: "12 PASS, 8 WARN, 3 BLOCK, 27 not yet scanned." The CLI already supports directory scanning; the missing piece is a roll-up summary report across multiple skills with an aggregate risk score. This is a one-page HTML or Markdown output that the security team can share with management. Implementation: a `--summary` flag on `skillscan scan <dir>` that emits a summary table in addition to per-skill reports.

**Skill registry integration.** Enterprise buyers want to maintain an approved skill registry — a versioned list of skills that have passed scan and are approved for deployment. SkillScan should be able to query a registry ("is version 1.2.3 of `meeting-summarizer` approved?") and update it ("mark this version approved, expires 90 days"). This can start as a simple JSON file in a private repo with a CLI command to query and update it, before becoming a SaaS API endpoint. It is the foundation of the SaaS token system and should be designed with that in mind.

**SIEM/SOAR integration.** The scan JSON output should be consumable by Splunk, Elastic, and Microsoft Sentinel without custom transformation. Requirements: a stable, versioned JSON schema; a SARIF output option (already in the SaaS roadmap — pull forward for the offline product); and documentation of the schema with field-level descriptions. Enterprise security teams will not pay for a tool that requires custom integration work. The SARIF output is already partially implemented; completing it and documenting the schema is a half-day task.

**Continuous monitoring mode.** Watch a directory or GitHub repository and re-scan whenever a SKILL.md changes; alert on regressions. This is the natural SaaS feature but it can be approximated offline with a cron job and the existing CLI. Worth documenting as a supported workflow pattern even before building native support. The public scan feed (M14) uses this pattern already — the same architecture applies to private enterprise registries.

### SaaS (post-v1.0, after quality bar is met)

The SaaS scanner is explicitly deferred until the offline product meets the quality bar: FPR ≤ 2%, macro F1 ≥ 0.90, and the known gaps listed below are closed. The following items define what "excellent" means before SaaS is offered.

**Known gaps to close before SaaS:**

| Gap | Current state | Target |
|---|---|---|
| ML injection recall | F1 = 0.786 (12 eval examples scoring 0.0 on obfuscation variants) | F1 ≥ 0.85 |
| ML FPR | 15.7% | ≤ 5% |
| Chain rule proximity window | Whole-document match (too broad) | 30-line window (M6) |
| PSV rules in rule YAML | Implemented in graph, not surfaced as standard findings | Wired (M8) |
| Intel DB depth | 2,051 IOC entries, 35 vuln packages | 5,000+ IOC, 150+ vuln packages (M5) |
| Similarity / clone detection | Not implemented | Complete (M17) |

**SaaS architecture prerequisites (spec when quality bar is met, not before):**

- Scan API (`POST /v1/scan`, webhook delivery, job polling)
- Token system and customer account model
- Signed PDF report delivery with customer watermark
- Data processing agreement template (customers send skill files to SkillScan infrastructure)
- Tiered model access: base tier (one model), premium tier (multi-model comparison)
- Rate limiting, abuse prevention, and SLA definition
- Privacy-preserving scan option: agent runs in customer's environment, only the report is returned

The SaaS architecture should be specced as a dedicated document when the time comes, not added incrementally to this roadmap.

---

## Scanning Tiers

### Cost structure

The three cost drivers determine what each tier can afford to include.

| Driver | Approximate cost | Notes |
|---|---|---|
| Static scan | ~$0.00 | Runs locally; CPU only; no API calls |
| ML classifier inference | ~$0.00 | Offline ONNX model; no API calls |
| Dynamic trace (1 model, 3 inputs) | ~$0.05–0.15 | LLM API calls for the traced model |
| Dynamic trace (3 models, 3 inputs each) | ~$0.30–0.60 | Parallelized; 3× the above |
| Report compiler (LLM render) | ~$0.02–0.05 | One LLM call to compile the final report |
| Badge issuance | ~$0.00 | Static SVG + registry write |

A free GitHub-triggered scan must cost effectively nothing. A paid scan can absorb LLM API costs because the price covers them. An enterprise report can absorb multi-model trace costs because the price is per-engagement, not per-scan.

---

### Tier definitions

#### Tier 0 — Community (free, GitHub-triggered)

**Who it serves:** Open-source skill publishers who want a trust signal without paying anything.

**How it works:** A GitHub Action (or webhook) triggers a static scan on every push to a repo containing a SKILL.md. The scan runs entirely offline — no LLM API calls. The result is a badge that appears in the README.

**What is included:**

- Full static analysis (117+ rules, chain rules, IOC/vuln DB lookup)
- ML classifier (offline ONNX, no API cost)
- Skill graph and permission scope validation
- Badge issued on PASS: `SkillScan Community — Static PASS — vX.Y.Z — YYYY-MM-DD`
- Badge issued on BLOCK: `SkillScan Community — Issues Found — view report`
- Public summary report (finding count by severity, no finding detail) linked from the badge
- Re-scans automatically on every push

**What is not included:** Dynamic trace, multi-model comparison, full finding detail in the public report, suppression workflow, file integrity manifest, policy profiles.

**Badge appearance:** Gray/silver. Clearly labeled "Static scan only." Expiry: none (re-scans on push, badge updates automatically).

**Cost to SkillScan:** ~$0.00 per scan. Sustainable at any volume.

---

#### Tier 1 — Verified (paid, per-skill or subscription)

**Who it serves:** Skill publishers who want a stronger trust signal and are willing to pay for it. Marketplace operators who want to display a credible badge on listed skills.

**How it works:** Publisher submits a skill (or connects their repo). SkillScan runs static analysis plus a single-model dynamic trace (3 fuzz inputs, standard canary tool surface). The LLM compiler renders a full report. A Verified badge is issued on PASS.

**What is included:**

- Everything in Tier 0
- Dynamic trace: 1 model (claude-sonnet or equivalent), 3 fuzz inputs, full canary tool surface (14 tools including email, calendar, GitHub, Slack, Notion)
- Full finding detail in the report (evidence lines, trace behavioral narrative, canary relay summary)
- File integrity manifest (SHA-256 + source URL for every file analyzed)
- Suppression workflow with audit trail
- Dependency vulnerability section (pip/npm packages cross-referenced against vuln DB)
- Badge issued on PASS: `SkillScan Verified — PASS — vX.Y.Z — YYYY-MM-DD`
- Badge issued on BLOCK: `SkillScan Verified — BLOCK — view report`
- Report PDF delivered to publisher
- 90-day approval window; badge expires and prompts re-scan after 90 days

**What is not included:** Multi-model trace, policy profiles, bulk scanning, SIEM integration.

**Badge appearance:** Green with a checkmark. "Verified" label. Shows expiry date. Links to the full report PDF.

**Suggested pricing:** ~$9–19 per scan, or ~$49/month for unlimited re-scans on a single skill. Pricing should cover ~3–5× the LLM API cost per scan.

**Cost to SkillScan:** ~$0.10–0.20 per scan (trace + compiler). Margin is strong at the suggested price.

---

#### Tier 2 — Professional (paid, per-engagement or annual subscription)

**Who it serves:** Enterprise teams scanning internal skills before deployment. Security consultants delivering SkillScan reports to clients.

**How it works:** Submits a batch of skills (or a directory). SkillScan runs static analysis plus a multi-model dynamic trace (2–3 models in parallel, 3 fuzz inputs each). The LLM compiler renders a full report with the multi-model comparison section. A Professional badge is issued per skill on PASS.

**What is included:**

- Everything in Tier 1
- Multi-model trace: 2–3 models (e.g., claude-sonnet + gpt-4.1), results compared and divergences flagged
- Policy profiles: customer-defined YAML mapping finding IDs to PASS/WARN/BLOCK thresholds
- Bulk scan summary dashboard: roll-up table across all skills in the batch
- Delta / baseline comparison: "3 new findings since last scan, 1 resolved"
- SARIF output for GitHub Advanced Security / Azure DevOps integration
- Machine-readable JSON report (stable schema, versioned) for SIEM/SOAR
- Badge issued on PASS: `SkillScan Professional — PASS — 3 models — vX.Y.Z — YYYY-MM-DD`
- Signed PDF report with customer watermark (tamper-evident)
- 90-day approval window per skill; re-scan on change

**What is not included:** Continuous monitoring (watch mode), skill registry API, regression alerts (these are SaaS-tier features requiring persistent infrastructure).

**Badge appearance:** Gold/dark. "Professional — Multi-model verified." Shows model count and expiry. Links to the signed report.

**Suggested pricing:** ~$99–299 per engagement (up to 10 skills), or ~$499/month for a team with unlimited scans. Enterprise annual contract pricing on request.

**Cost to SkillScan:** ~$0.40–0.80 per skill (multi-model trace + compiler). Margin is strong at engagement pricing; requires volume discipline at subscription pricing.

---

#### Tier 3 — Enterprise API (SaaS, post-v1.0)

**Who it serves:** Large enterprises and platform operators who need to scan skills programmatically at scale — e.g., a marketplace that scans every submitted skill before listing, or an enterprise that scans every skill on every PR merge.

**How it works:** REST API (`POST /v1/scan`). Customer sends the skill file content (or a GitHub URL). SkillScan runs the full scan pipeline in its cloud infrastructure and delivers the report via webhook or polling. Persistent customer account, registry, and regression alert infrastructure.

**What is included:**

- Everything in Tier 2
- Scan API with webhook delivery and job polling
- Skill registry: approved version tracking, expiry management, query endpoint
- Continuous monitoring: watch a GitHub repo, re-scan on SKILL.md change, alert on regression
- Regression alerts: email/webhook when a new finding appears in a previously-passing skill
- Skill signing: SkillScan issues a signed attestation embedded in the skill front-matter
- SLA: 99.9% uptime, scan completion within 5 minutes for Tier 1-equivalent, 15 minutes for multi-model

**Pricing model:** Per-scan credits (volume discounts), or annual contract with a scan allowance. Pricing TBD when specced.

**Prerequisite quality bar before offering Tier 3:** FPR ≤ 5%, macro F1 ≥ 0.90, all known gaps in the SaaS prerequisites table closed. Do not offer Tier 3 until the product is excellent — a bad scan at scale does more reputational damage than no SaaS at all.

---

### Tier comparison

| Feature | Tier 0 Community | Tier 1 Verified | Tier 2 Professional | Tier 3 Enterprise API |
|---|:---:|:---:|:---:|:---:|
| Static analysis (117+ rules) | Yes | Yes | Yes | Yes |
| ML classifier (offline) | Yes | Yes | Yes | Yes |
| IOC / vuln DB lookup | Yes | Yes | Yes | Yes |
| Dynamic trace (1 model) | No | Yes | Yes | Yes |
| Dynamic trace (multi-model) | No | No | Yes | Yes |
| Full finding detail in report | No | Yes | Yes | Yes |
| File integrity manifest | No | Yes | Yes | Yes |
| Dependency vuln section | No | Yes | Yes | Yes |
| Policy profiles | No | No | Yes | Yes |
| Bulk scan summary | No | No | Yes | Yes |
| Delta / baseline comparison | No | No | Yes | Yes |
| SARIF / JSON output | No | No | Yes | Yes |
| Signed PDF report | No | No | Yes | Yes |
| Skill registry | No | No | No | Yes |
| Continuous monitoring | No | No | No | Yes |
| Regression alerts | No | No | No | Yes |
| Skill signing | No | No | No | Yes |
| Badge color | Silver | Green | Gold | Gold + API |
| Badge expiry | None (auto-refresh) | 90 days | 90 days | Managed |
| Approx. cost per scan | $0 | $9–19 | $99–299/engagement | TBD |

### Badge design principles

Badges are the primary distribution mechanism for Tier 0 and Tier 1. A few design constraints that matter:

**The badge must be honest about what was scanned.** A Community badge that says "PASS" but only ran static analysis must clearly say "Static scan only" — it should not look identical to a Verified badge that ran a full trace. Buyers who see the badge in a marketplace need to be able to distinguish the two at a glance. Color coding (silver vs. green vs. gold) plus a tier label achieves this.

**Expiry is a feature, not a limitation.** A badge that expires after 90 days and prompts re-scan is more valuable than a badge that never expires, because it tells the buyer the scan is current. The expiry date should be visible on the badge. A badge that expired 6 months ago is worse than no badge.

**The badge links to the report, not just a status page.** The full report (or at minimum the public summary for Tier 0) must be accessible from the badge URL. This is what makes the badge credible — anyone can verify the claim by reading the evidence.

**Tier 0 badges are issued for free but are rate-limited.** A publisher can get one free badge per skill per day (re-scan on push). Abuse prevention: rate limit by GitHub repo, not by IP.
