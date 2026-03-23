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
