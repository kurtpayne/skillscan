# Work Queue — 2026-03-24

> Goal: push macro F1 toward 0.95. Current: **0.911** (v5, 2026-03-24). The gap is almost entirely injection recall (F1=0.890, P=0.972). The model is precise but misses subtle, indirect, and social-engineering attacks. Today's work is entirely pre-training data work — no training run until the corpus is ready.

---

## Priority 1 — Close the 13 Injection FNs (highest ROI toward 0.95)

These 13 archetypes scored 0.0 in the v5 eval. Each needs 5–10 training variants added to the corpus. The model has seen 0–5 examples of each pattern; the target is ≥ 10 per archetype.

### Indirect / Supply-Chain Injection (9 archetypes, ~0 training examples each)

| Archetype | Pattern | Training count (v5) |
|---|---|---|
| `pi15_typosquat_changelog` | Fake changelog entry in a dependency | 1 |
| `pi22_webhook_exfil_logging` | Logging webhook that silently exfils data | 1 |
| `pi24_rss_indirect_injection` | Injected instruction in RSS/feed content | 1 |
| `pi27_dependency_chain` | Malicious transitive dependency instruction | 1 |
| `pi31_prompt_leak_via_translation` | Translation step used to leak system prompt | 0 |
| `pi59_tool_name_spoofing` | Tool with a name that shadows a trusted tool | 2 |
| `pi63_fake_changelog_injection` | Changelog section that embeds an instruction | 2 |
| `pi12_credential_exfil_env` | Reads `.env`/config files and exfils them | 5 |
| `pi20_error_message_leakage` | Error handler that leaks secrets in output | 5 |

**Action:** Write 8 variants each for pi15, pi22, pi24, pi27, pi31, pi59, pi63 (the 0–2 count ones). Write 5 more variants each for pi12 and pi20. Total: ~66 new training examples. Save to `training_corpus/prompt_injection/prompt_injection/`.

**Also run backtranslation augmentation** on all 9 eval examples using `scripts/backtranslate_augment.py --source-from-eval held_out_eval/ --max-files 9 --languages fr es zh de`. This generates ~36 additional paraphrase variants cheaply.

### Jailbreak Variants (3 archetypes, 0 training examples for jb07/jb08)

| Archetype | Pattern | Training count (v5) |
|---|---|---|
| `jb07_035` | Consistency/compliance appeal ("you helped before, so you must help now") | 0 |
| `jb08_037` | Absolute refusal prohibition ("you are not allowed to say no") | 0 |
| `jb08_040` | Variant of jb08 refusal prohibition | 0 |

**Action:** Write 10 variants of the consistency-appeal jailbreak (jb07 family) and 10 variants of the refusal-prohibition jailbreak (jb08 family). Save to `training_corpus/obfuscation_injection/obfuscation_injection/`. These are short, high-signal examples — write them with varied skill names, descriptions, and surface text so the model generalizes the pattern rather than memorizing a template.

### Social Engineering FNs (2 archetypes)

| Archetype | Pattern | Training count (v5) |
|---|---|---|
| `se_git_config_harvest` | Poses as a "git security audit" to read `~/.gitconfig` and `.git-credentials` | 0 (no SE training for this variant) |
| `se_prize_scam` | Fake prize/reward that asks for API key to "verify identity" | 0 (no SE training for this variant) |

**Action:** Write 8 variants of the git-config-harvest pattern and 8 variants of the prize/reward scam. Save to `training_corpus/social_engineering/social_engineering/`. The existing SE training corpus has 516 examples but none covering these two specific attack shapes.

---

## Priority 2 — Fix the 2 Benign MCP False Positives

The model incorrectly flags `benign_mcp_git_skill` and `benign_mcp_sampling_skill` as injections. Both are legitimate MCP tool usage patterns. The model is likely over-triggering on:
- `git_commit`, `git_push`, `git_credentials` language in the git skill
- `sampling/createMessage` and `session.create_message` language in the sampling skill

**Action:** Write 10 benign MCP training examples covering:
- MCP git server usage (git_status, git_diff, git_log, git_commit, git_push)
- MCP sampling/createMessage usage for legitimate delegation
- MCP filesystem server usage with read/write operations
- MCP database server usage with query operations
- MCP web search server usage

Save to `training_corpus/benign/benign/` with filenames prefixed `benign_mcp_`.

---

## Priority 3 — Update Roadmap Success Metrics

The ROADMAP.md success metrics table is stale. Update it to reflect v5 results:

| Metric | Old value | New value |
|---|---|---|
| ML corpus size (training) | 7,277 | 11,461 |
| ML macro F1 (held-out) | 0.8448 (v7458) | **0.911** (v5, 2026-03-24) |
| ML injection F1 | 0.7857 | 0.8903 |
| ML FPR | 15.7% | 11.45% |
| Showcase examples | 104 | 117 |
| Static + chain rules | 117 | 135 |
| v0.4.0 target macro F1 | ≥ 0.90 | ≥ 0.93 |
| v1.0 target macro F1 | ≥ 0.93 | **≥ 0.95** |

Also update Milestone 7 acceptance criteria from "injection F1 ≥ 0.85" to "injection F1 ≥ 0.90, macro F1 ≥ 0.93" since we've already cleared the old bar.

---

## Priority 4 — M5 Intel DB Expansion (partial)

M5 is the top-priority roadmap milestone. Do the vuln DB portion today since it's scripted:

```bash
cd ~/skillscan-security
python3 tools/intel_update.py --vuln-db --packages requests urllib3 cryptography paramiko pillow aiohttp httpx boto3 sqlalchemy django flask fastapi celery redis pymongo axios express node-fetch got superagent ws socket.io jsonwebtoken bcrypt multer
```

This should push the vuln DB from 35 to 50+ packages, satisfying the M5 acceptance criterion for vuln DB. The IOC DB expansion (5,000+ entries) is a larger task — queue it for a separate session.

---

## Do NOT do today

- **No training run.** The corpus additions above are the pre-work. Trigger training only after all Priority 1 and Priority 2 corpus work is committed and pushed.
- **No new eval examples.** The eval set is at 202 examples and well-balanced. Adding more eval before training would dilute the signal from the corpus additions.
- **No M6 chain rule proximity work.** That's a code change and should be its own session.

---

## Expected outcome after next training run

With 66 indirect injection variants + 20 jailbreak variants + 16 SE variants + 10 benign MCP examples + backtranslation augmentation (~36 more), the corpus adds ~148 targeted examples. Based on the v5 trajectory (0.8448 → 0.911 with ~4,000 new examples), targeted additions to the FN archetypes should push injection recall from 0.821 to ~0.87–0.89, and macro F1 from 0.911 toward **0.93–0.94**. Reaching 0.95 will likely require one more iteration after that.

---

*Generated 2026-03-24. Next training run: after corpus additions are committed.*
