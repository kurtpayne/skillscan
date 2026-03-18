# SkillScan Security — Roadmap

*Last updated: March 2026. Reflects a full codebase audit conducted at v0.3.1.*

---

## Current State (v0.3.1)

The scanner is a functioning, well-structured Python CLI with a clean separation between the detection engine, rule data, and output layer. The core architecture is sound and the test suite (30 test files, ~5,500 lines) covers the main detection paths well. The following is an honest accounting of where things stand.

**What works well.** The static rule engine is reliable and deterministic. The instruction hardening pipeline (Unicode normalization, zero-width stripping, bounded base64 decode) handles the most common obfuscation vectors. The policy engine is flexible and the three built-in profiles cover the main operator personas. The SARIF/JUnit/JSON output formats are complete and CI-ready. The corpus pipeline and Modal-based fine-tune workflow are operational. Ruff, mypy, and the adversarial regression suite all pass cleanly.

**Honest gaps.** The IOC and vulnerability databases are extremely thin: 11 domains, 7 IPs, 0 CIDRs, 3 URLs in the IOC DB; 2 Python packages and 2 npm packages in the vuln DB. These numbers make the intel layer largely decorative at present. The ML corpus is at 115 examples (54 benign / 61 injection) — the fine-tuned adapter exists and runs, but the training set is too small to trust the model's precision on out-of-distribution inputs. The `docs/DETECTION_MODEL.md` referenced in Milestone 4 does not exist yet. The VS Code extension scaffold is present but unpublished. The `window_lines` proximity constraint for chain rules is not implemented. PINJ-GRAPH-004 (cross-skill tool escalation) is referenced in docs but not implemented.

| Area | Status |
|---|---|
| Static rule engine | Solid — 69 static + 15 chain rules across 3 packs |
| Chain rule evaluation | Works, but no proximity constraint (whole-document match) |
| Instruction hardening | Complete |
| Policy engine | Complete — 3 profiles + custom YAML |
| IOC database | Thin — 21 entries total |
| Vuln database | Thin — 4 package/version entries |
| ML detection | Operational but undertrained (115 examples) |
| Skill graph detector | 3 of 4 planned rules implemented |
| AI assist | Works — Anthropic/OpenAI/Ollama providers |
| SARIF / JUnit / JSON output | Complete |
| VS Code extension | Scaffolded, not published |
| Pre-commit hook | Published (`skillscan-security>=0.3.1`) |
| Docker image | Published (`kurtpayne/skillscan-security:v0.3.1`) |
| PyPI package | Published (`skillscan-security==0.3.1`) |
| Homebrew formula | Scaffolded, not submitted to homebrew-core |
| `docs/DETECTION_MODEL.md` | Does not exist |
| Test coverage | Good on core paths; ML, remote, and ClamAV tests use mocks |

---

## Milestone 5 — Intel & Vuln DB Depth (1 week)

The intel layer is the most visibly thin part of the project. A scanner that finds 11 IOC domains looks like a demo, not a tool. This milestone makes the bundled data credible.

### Issue H1 — Expand IOC database to a defensible baseline

The current IOC DB has 11 domains and 7 IPs. The target is 150+ domains, 50+ IPs, and 10+ CIDRs sourced from public threat intelligence feeds (abuse.ch URLhaus, PhishTank, OpenPhish, Feodo Tracker, and the existing GlassWorm/PylangGhost campaign data). The automated `signature-update` agent (runs twice daily) should be the primary growth mechanism going forward, but the initial seeding should be done manually to establish a credible baseline.

**Acceptance criteria:** IOC DB contains ≥150 domains, ≥50 IPs, ≥10 CIDRs. All entries have a `source` and `added` field. The `ioc_db.json` schema is extended to support per-entry provenance.

### Issue H2 — Expand vulnerability database to cover the top MCP ecosystem packages

The vuln DB covers 2 Python packages and 2 npm packages. The target is coverage of the 20 most-installed MCP-adjacent packages in both ecosystems, sourced from OSV.dev and the GitHub Advisory Database. The `@awslabs/aws-api-mcp-server` CVE-2026-4270 entry already exists — this milestone adds the surrounding ecosystem.

**Acceptance criteria:** Vuln DB covers ≥20 packages across Python and npm. Each entry includes CVE/GHSA ID, affected version range, fixed version, and CVSS score. A CI step validates that all vuln DB entries have a corresponding CVE/GHSA reference.

### Issue H3 — Automated IOC/vuln DB update agent (twice-daily)

The `signature-update` agent should run on a schedule (twice daily) and update `ioc_db.json` and `vuln_db.json` from the configured public feeds. It should open a PR with a diff summary rather than committing directly to main, so the pattern-update-guard workflow can validate hygiene before merge.

**Acceptance criteria:** Agent runs on schedule. PRs include a structured diff summary (entries added/removed/changed). The pattern-update-guard workflow validates the PR before merge.

---

## Milestone 6 — Chain Rule Precision (2 weeks)

*Sourced from external review, March 2026.*

### Issue G1 — Document and validate chain confidence uplift rationale

CHN-002 (0.92) correctly exceeds its constituent EXF-001 (0.90) because co-occurrence of `secret_access` + `network` is a stronger intent signal than either pattern alone. CHN-001 (0.95) matches its constituent MAL-001 (0.95) because the static rule already encodes the conjunction in a single regex — no uplift is warranted. This asymmetry is correct but undocumented.

Add an optional `confidence_rationale` field to `ChainRule` (surfaced in `rule list --format json`). Document the uplift policy in `CONTRIBUTING.md`. Add a CI lint step that warns when a new chain rule's confidence falls below its highest-confidence constituent.

**Acceptance criteria:** All 15 chain rules have a `confidence_rationale` value. CI warns on confidence regression. `rule list --format json` includes the field.

### Issue G2 — action_patterns dual-use audit and static rule gap analysis

`action_patterns` serves two roles: the substrate for chain detection, and a softer detection layer that can fire chain rules without any individual static rule triggering. A bare `https://` URL + a `.env` reference hits CHN-002 but does not trigger EXF-001. This is intentional but creates an undocumented detection surface.

Audit all 19 `action_patterns` entries and classify each as `static_backed` or `chain_only`. For chain-only paths, decide explicitly: promote to a standalone static rule, keep with a documented rationale, or tighten the pattern. Document in `docs/DETECTION_MODEL.md`.

**Acceptance criteria:** Every `action_patterns` entry is classified. `docs/DETECTION_MODEL.md` exists and covers the detection model. No new entries are added without classification.

### Issue G3 — Proximity constraint (window_lines) for chain rules

The engine fires chain rules when constituent patterns appear anywhere in the full file text, regardless of distance. CHN-001 fires if `curl` appears on line 3 and `bash` appears on line 200, even if unrelated. This is a documented false-positive source for long skills.

Add an optional `window_lines: int` field to `ChainRule` (YAML schema + Pydantic model + engine). When set, the engine only fires if all constituent patterns match within a sliding window of that many lines. CHN-001 and CHN-002 are the first candidates (suggested: 30–50 lines), validated against the benchmark corpus before committing to values.

**Acceptance criteria:** `window_lines` is parsed and respected by the engine. Existing rules without the field are unaffected. CHN-001 and CHN-002 have validated `window_lines` values. False-positive rate on the benign corpus does not increase.

---

## Milestone 7 — Corpus Growth & Model Quality (2 weeks)

The ML adapter is trained on 115 examples. That is enough to demonstrate the pipeline works, not enough to trust the model's precision in production. The target is 300+ examples with a documented evaluation protocol.

### Issue I1 — Corpus expansion to 300+ examples

The current corpus has 54 benign and 61 injection examples. The benign side is almost entirely synthetic (50 of 54 examples from `seed_corpus.py`). The injection side has good diversity (43 hand-crafted + adversarial cases) but is thin on real-world examples.

Priority additions: (1) real benign skills scraped from ClawHub and skills.sh — these are the most important because synthetic benign examples may not capture the full distribution of legitimate skill patterns; (2) additional injection variants for the attack classes that are currently underrepresented (indirect injection via external data, multi-turn memory poisoning, YAML block scalar injection).

**Acceptance criteria:** Corpus reaches ≥300 examples. Benign/injection ratio stays within 45/55–55/45. At least 50 benign examples are from real-world sources (not synthetic). CORPUS_CARD.md is updated.

### Issue I2 — Evaluation protocol and held-out test set

There is no held-out evaluation set and no documented precision/recall numbers for the fine-tuned adapter. The model card on HuggingFace references the base model's 95.25% accuracy on a 20k held-out set, not the fine-tuned adapter's performance on the SkillScan-specific distribution.

Reserve 20% of the corpus as a held-out test set before fine-tuning. Add an evaluation step to `finetune_modal.py` that computes precision, recall, F1, and false-positive rate on the held-out set and writes results to `corpus/EVAL_RESULTS.md`. Gate fine-tune pushes on F1 ≥ 0.90 on the held-out set.

**Acceptance criteria:** Held-out set exists and is excluded from training. `corpus/EVAL_RESULTS.md` is generated on each fine-tune run. F1 gate is enforced in the corpus-sync workflow.

### Issue I3 — graph_injection corpus coverage

The `corpus/graph_injection/` directory exists with examples for PINJ-GRAPH-001/002/003 but these examples are not included in the ML training corpus. They should be: graph injection attacks are a distinct semantic class that the base model has not seen.

**Acceptance criteria:** All `graph_injection/` examples are included in the training corpus with label `injection`. Corpus manifest reflects the addition.

---

## Milestone 8 — Skill Graph Completion (1 week)

### Issue J1 — PINJ-GRAPH-004: cross-skill tool escalation detection

The skill graph detector currently covers remote `.md` loading (PINJ-GRAPH-001), high-risk tool grants without declared purpose (PINJ-GRAPH-002), and memory file write instructions (PINJ-GRAPH-003). PINJ-GRAPH-004 — cross-skill tool escalation, where a skill invokes another skill and the invoked skill has higher tool permissions than the invoking skill — is referenced in docs and the CHANGELOG but not implemented.

The detection logic requires comparing tool grants across a multi-skill scan context. The `skill_graph.py` detector already has `_SKILL_REF_RE` for detecting skill references; the missing piece is a second pass that resolves referenced skills within the scan target and compares their tool grants.

**Acceptance criteria:** PINJ-GRAPH-004 fires when a skill references another skill that grants a higher-risk tool than the referencing skill declares. The rule is covered by at least two adversarial fixtures and one benign fixture. The adversarial suite expectations are updated.

### Issue J2 — Skill graph corpus examples for PINJ-GRAPH-004

Add adversarial fixtures for PINJ-GRAPH-004 to `tests/adversarial/cases/` and `corpus/graph_injection/`. Update `tests/adversarial/expectations.json`.

---

## Milestone 9 — VS Code Extension Publish (1 week)

The extension scaffold in `editors/vscode/` is complete: TypeScript source, SARIF parsing, inline diagnostics, status bar, and a marketplace publish workflow. The only blockers are a registered publisher ID and a `VSCE_PAT` secret.

### Issue K1 — Publish to VS Code Marketplace

Register the `skillscan` publisher on the VS Code Marketplace. Add `VSCE_PAT` to repo secrets. Trigger the publish workflow. The extension should install cleanly and show inline diagnostics on SKILL.md files.

**Acceptance criteria:** Extension is live on the VS Code Marketplace. Install count is tracked. The `editors/vscode/README.md` is updated with install instructions.

### Issue K2 — Extension auto-update on rule sync

When the user runs `skillscan rule sync`, the extension should detect the updated rules and re-run diagnostics on open files without requiring a VS Code restart.

**Acceptance criteria:** Diagnostics refresh automatically after `skillscan rule sync` completes. No VS Code restart required.

---

## Milestone 10 — Detection Model Documentation (3 days)

The roadmap has referenced `docs/DETECTION_MODEL.md` since Milestone 4. It does not exist. This is the single most important missing document for external contributors and security reviewers.

### Issue L1 — Write docs/DETECTION_MODEL.md

The document should cover: the detection pipeline stages and their order; the static rule schema and confidence calibration policy; the chain rule schema, uplift rationale policy, and (once implemented) windowed-matching semantics; the `action_patterns` classification table (`static_backed` vs `chain_only`); the local semantic classifier (NLTK/Porter stemmer, feature categories, scoring); the ML detector (base model, fine-tune pipeline, staleness policy); the AI assist layer (provider config, prompt version, snippet limits, policy integration); and the policy scoring model (severity weights, threshold semantics, hard-block rules).

**Acceptance criteria:** `docs/DETECTION_MODEL.md` exists and covers all seven detection layers. It is linked from `README.md` and `CONTRIBUTING.md`. The `action_patterns` classification table is complete.

---

## Milestone 11 — Hardening & Operational Maturity (ongoing)

These items do not have a fixed milestone but should be addressed before a v1.0 release.

**Test coverage for ML and remote paths.** The `test_ml_detector.py` and `test_remote.py` tests use mocks throughout. At least one integration test per module should run against real artifacts (gated behind a `--integration` marker and skipped in standard CI).

**ClamAV integration test.** `test_clamav.py` mocks the `clamscan` binary. The Docker image includes ClamAV and enables it by default; there should be at least one end-to-end test that runs inside the Docker image and verifies ClamAV findings appear in the report.

**Suppression file expiry enforcement in CI.** The suppression module supports expiry dates but there is no CI step that warns when suppressions are approaching expiry. Add a `skillscan suppress check` subcommand that exits non-zero when any active suppression expires within 30 days.

**Homebrew formula submission.** The formula in `packaging/homebrew/` is scaffolded but not submitted to homebrew-core or a tap. Submit to a `homebrew-skillscan` tap as a first step; homebrew-core submission can follow after v1.0.

**Release smoke test.** The release checklist references smoke tests but there is no automated post-release verification. Add a workflow that triggers on published releases, installs from PyPI and Docker Hub, and runs `skillscan scan tests/fixtures/malicious/openclaw_compromised_like` with an expected `block` verdict.

**`docs/DETECTION_MODEL.md` referenced but missing.** Covered in Milestone 10.

---

## Deprioritized / Deferred

The following items from earlier roadmap drafts are explicitly deprioritized until the above milestones are complete.

**SaaS control plane / multi-tenant API.** Out of scope per PRD. Revisit post-v1.0 if adoption warrants it.

**Automatic code remediation.** Out of scope per PRD. The scanner's job is to surface findings, not rewrite code.

**Public signing and transparency log workflow.** The SBOM pipeline (CycloneDX + cosign) is already in place. Full Sigstore/Rekor integration can wait until the project has meaningful downstream consumers.

**Channel support (stable/preview/labs).** The rule sync mechanism works against `main`. Channel support adds complexity without clear benefit at the current scale.

**Baseline diff mode as a separate milestone.** `skillscan diff` is already implemented. The remaining work (suppression file integration with diff output) is a small feature, not a milestone.

---

## Risks & Guardrails

**False positives from semantic detection.** Guardrail: semantic findings are advisory by default; require evidence snippets; ML findings are gated at 0.70 threshold.

**Performance regressions from extra scanners.** Guardrail: strict budgets (timeout, bytes, files), benchmark gates in CI.

**Distribution drift / broken installs.** Guardrail: release smoke tests for `pip` and Docker on each tag (Milestone 11).

**Complexity creep.** Guardrail: keep features optional and policy-driven; preserve deterministic core.

**Thin intel data making the scanner look like a demo.** Guardrail: Milestone 5 is the highest-priority milestone. Do not ship v0.4.0 without credible IOC and vuln DB depth.

---

## Success Metrics

| Metric | Current | Target (v0.4.0) | Target (v1.0) |
|---|---|---|---|
| IOC DB entries | 21 | 200+ | 500+ (automated) |
| Vuln DB packages | 4 | 20+ | 50+ |
| ML corpus size | 115 | 300+ | 500+ |
| ML adapter F1 (held-out) | unknown | ≥0.90 | ≥0.93 |
| Static + chain rules | 84 | 90+ | 100+ |
| Adversarial cases | 25 | 35+ | 50+ |
| VS Code extension | scaffolded | published | 100+ installs |
| Time-to-first-scan | &lt;5 min | &lt;3 min | &lt;2 min |
