---
language: en
license: apache-2.0
library_name: transformers
tags:
  - security
  - prompt-injection
  - skill-scanning
  - deberta
  - lora
  - onnx
  - ai-safety
  - agent-security
base_model: microsoft/deberta-v3-base
pipeline_tag: text-classification
---

# SkillScan DeBERTa Adapter — `kurtpayne/skillscan-deberta-adapter`

A LoRA-fine-tuned DeBERTa-v3-base adapter for detecting **prompt injection, jailbreaks, malicious instructions, and supply-chain attacks** in AI agent skill files (SKILL.md format). This model is the ML detection layer inside the [`skillscan`](https://github.com/kurtpayne/skillscan-security) CLI scanner.

> **Intended deployment:** This model is not designed for direct HuggingFace inference. It is downloaded and run locally by the `skillscan` CLI via ONNX runtime. No network calls occur at scan time. See [How to Use](#how-to-use).

---

## Model Description

### Architecture

| Component | Detail |
|---|---|
| Base model | `microsoft/deberta-v3-base` |
| Fine-tuning method | LoRA (Low-Rank Adaptation), r=64, alpha=128 |
| Task | Binary sequence classification: `BENIGN` / `INJECTION` |
| Inference format | ONNX FP32 (~350 MB) |
| Runtime | ONNX Runtime (CPU), no GPU required |
| Input | Raw SKILL.md file text, chunked to 512 tokens with 64-token stride |
| Output | Per-chunk injection probability; file verdict is max-pool over chunks |

The model uses a sliding-window chunking strategy to handle SKILL.md files of arbitrary length. Each 512-token chunk is scored independently; the file verdict is the maximum injection probability across all chunks. This ensures that a single malicious instruction buried deep in a large file is not diluted by surrounding benign content.

### What it detects

The model is trained to flag the following attack categories in AI agent skill files:

| Category | Examples |
|---|---|
| **Prompt injection** | Role overrides, fake system headers, goal hijacking, context extraction |
| **Jailbreaks** | DAN-style, consistency appeals, refusal prohibitions, developer mode |
| **Indirect injection** | RSS feed poisoning, tool result injection, "when you read this" triggers |
| **Exfiltration** | DNS exfil, webhook callbacks, error message + secret patterns |
| **Supply chain** | Malicious `pip install` hooks, `setup.py` backdoors, package name typosquatting |
| **Social engineering** | Urgency framing, prize/reward scams, credential verification pretexts |
| **MCP-specific attacks** | Tool name spoofing, sampling exfiltration, multi-agent hijack |

### What it does not detect

The model has known limitations. These are not gaps to be closed with more rules — they reflect the hard ceiling of static offline analysis:

- **Runtime-conditional payloads:** Instructions that activate only when a specific date, environment variable, or API response is present. These require dynamic execution to detect.
- **Indirect injection from external content fetched at runtime:** A skill that fetches a malicious RSS feed or changelog at execution time cannot be flagged by static analysis of the skill file itself.
- **Infrastructure-level MCP trust:** Whether an MCP server at a given URL is legitimate cannot be determined from the skill file alone.
- **Semantic obfuscation at high sophistication:** Attacks encoded in multi-layer base64 + steganography + homoglyph substitution may evade detection if no training variants exist.

---

## Training Data

### Corpus composition (v9, current)

| Split | Count | Sources |
|---|---|---|
| Training — benign | ~9,900 | mattnigh/skills_collection, alirezarezvani/claude-skills, GitHub code search, Azure/AWS/Composio/ServiceNow vendor skill repos, OWASP cheat sheets, enterprise runbooks |
| Training — injection | ~8,261 | Manually crafted examples, fuzzer-generated variants, trace-verified adversarial examples, gap archetype expansions, backtranslation augments |
| **Training total** | **18,161** | |
| Held-out eval — benign | ~256 | Same sources as training, reserved before any fine-tune run |
| Held-out eval — injection | ~188 | Manually crafted + fuzzer-generated + organic (pattern-update agent discoveries) |
| **Held-out eval total** | **444** | Never included in training |

The held-out eval set was locked before the first fine-tune run and has never been used for training. It was expanded from 181 examples (v7458) to 444 examples (v16589) by reserving 218 new examples from the M7 corpus expansion before training began.

### Data sources and collection methodology

Benign examples were collected from public GitHub repositories containing real-world AI agent skill files. The corpus researcher agent (a scheduled GitHub Actions workflow) harvests vendor skill files from Azure, AWS, Composio, and ServiceNow repositories daily and adds them to the private corpus. All benign examples are reviewed to confirm they contain no actual attack content before training.

Injection examples were generated through three methods: (1) manual crafting by the project maintainer targeting specific attack archetypes, (2) automated fuzzing using the `skill-fuzzer` tool (5 mutation strategies: instruction override, exfil channel injection, social engineering, supply chain hook, obfuscation), and (3) trace-verified examples from the `skillscan-trace` behavioral harness that confirmed the attack caused measurable behavioral change in a live agent session.

### Corpus privacy

The full training corpus is maintained in a private repository (`kurtpayne/skillscan-corpus`) and is not publicly released. The held-out eval set composition is documented in `docs/MODEL_METRICS.md` in the public repo.

---

## Evaluation Results

All evaluations run against the held-out eval set (444 examples). The eval set was never used for training.

### Current model: v18161-5ep (v9)

| Metric | Value |
|---|---|
| Accuracy | 0.9797 |
| **Macro F1** | **0.9752** |
| False Positive Rate (FPR) | **1.89%** |
| False Negative Rate (FNR) | ~4.5% |
| Eval set size | 444 |
| Training corpus size | 18,161 |

### Version history

| Version | Corpus size | Macro F1 | FPR | Key improvement |
|---|---|---|---|---|
| v1278 | 1,278 | 0.2690 | 95.7% | Baseline — heavily injection-biased base model |
| v7458 | 7,277 | 0.8448 | 15.7% | First gate pass; corpus expansion from 210 → 7,277 |
| v11461 | 11,461 | 0.9110 | 11.45% | Enterprise benign corpus; MCP/SE coverage |
| v16589 | 16,589 | 0.9608 | 3.69% | Gap archetype closure; enterprise adversarial examples |
| **v18161** | **18,161** | **0.9752** | **1.89%** | **Current — both SaaS quality thresholds met** |

### Quality thresholds

| Threshold | Target | Current | Status |
|---|---|---|---|
| Macro F1 (v1.0) | ≥ 0.97 | 0.9752 | ✅ Met |
| False Positive Rate (SaaS gate) | ≤ 2% | 1.89% | ✅ Met |
| Enterprise benign FPR | ≤ 2% | 1.89% | ✅ Met |

### Known failure modes (persistent FN archetypes)

The following attack archetypes have lower-than-average recall. Each has fewer than 15 training examples, and the current examples may be too homogeneous for the model to generalize:

| Archetype | Description | Priority |
|---|---|---|
| `mcp_server_impersonation` | MCP tool name spoofing to redirect agent calls | High |
| `organic_mal047` | Claude hooks RCE via lifecycle callback injection | High |
| `se_git_config_harvest` | git config credential harvest via social engineering | High |
| `jb_jb07_035` | Jailbreak consistency appeal variant | Medium |
| `jb_jb08_037` | Jailbreak refusal prohibition variant | Medium |
| `jb_jb09_045`, `jb_jb10_046` | New jailbreak archetypes (zero training examples) | Medium |
| `pi24_rss_indirect_injection` | RSS-based indirect injection | Medium |
| `pi37_markdown_injection` | Markdown link injection (zero training examples) | Low |

These archetypes are tracked in `docs/MODEL_METRICS.md` and are the primary targets for the v10 corpus expansion.

---

## How to Use

This model is not intended for direct HuggingFace inference. It is downloaded and run locally by the `skillscan` CLI. No network calls occur at scan time — the model runs entirely on the local machine via ONNX Runtime.

### Install and run

```bash
pip install skillscan-security
skillscan model install          # downloads the ONNX adapter from HuggingFace (~350 MB)
skillscan scan path/to/skills/   # runs static rules + ML detection offline
```

### Check model status

```bash
skillscan model status           # shows installed version vs HF Hub latest
```

### Update to latest model

```bash
skillscan update                 # pulls latest rules, intel DB, and model in one command
```

### CI/CD usage (no model download)

```bash
skillscan scan path/to/skills/ --no-model   # static rules only, no ML layer
```

### Direct ONNX inference (advanced)

If you need to run the model outside of `skillscan`, the ONNX model can be loaded directly:

```python
import onnxruntime as ort
import numpy as np
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("microsoft/deberta-v3-base")
session = ort.InferenceSession("model.onnx")

text = open("path/to/skill.md").read()
inputs = tokenizer(text, return_tensors="np", truncation=True, max_length=512)
outputs = session.run(None, dict(inputs))
injection_prob = float(np.softmax(outputs[0][0])[1])
print(f"Injection probability: {injection_prob:.3f}")
```

Note: The `skillscan` CLI uses a sliding-window chunking strategy that is more accurate than single-pass inference for long files. Direct ONNX inference without chunking will produce less reliable results on files longer than 512 tokens.

---

## Detection Architecture

The ML model is one layer in `skillscan`'s multi-layer detection pipeline. Understanding the full architecture helps set expectations for what the model contributes vs. what other layers handle:

| Layer | Mechanism | What it catches |
|---|---|---|
| 1. IOC matching | Intel DB scan (5,500 entries: domains, IPs, CIDRs) | Known malicious domains and IPs embedded in skill content |
| 2. Static rules | Regex pattern matching (158 rules across 9 categories) | Known attack patterns, structural violations, dangerous constructs |
| 3. Chain rules | Multi-pattern proximity matching within a 40-line window | Attack sequences requiring co-occurrence (download + execute, etc.) |
| 4. Multilang rules | Language-gated regex (.js/.ts/.rb/.go/.rs files only) | Language-specific attack patterns in embedded scripts |
| 5. Python AST data-flow | Source-to-sink taint analysis (.py files only, stdlib `ast`) | Secret → decode → exec/network flows in embedded Python scripts |
| 6. Skill graph analysis | Graph-based PSV rules | Tool drift, circular dependencies, permission scope violations |
| **7. ML classifier** | **DeBERTa-v3 + LoRA (this model) · F1 0.9752 · FPR 1.89%** | **Novel phrasing, obfuscated attacks, semantic patterns no rule can express** |
| 8. Stemmed feature scorer | Porter-stemmed axis scoring via NLTK (`semantic_local.py`) | Multi-sentence intent distributed across text — jailbreaks and credential-harvest instructions not caught by single-line rules. No sentence structure or negation awareness. |
| 9. Vuln DB matching | Dependency scan (23 Python pkgs, 4 npm pkgs, 111 versions) | Known-vulnerable package versions in requirements.txt / package.json |
| 10. ClamAV (optional) | Signature-based AV scan (`--clamav` flag) | Known malware signatures in embedded script files (.py, .sh, .js…) |

The ML layer (Layer 7) is specifically valuable for attacks that use natural language variation to evade static rules — jailbreaks, social engineering, and indirect injection patterns where the attack is expressed in prose rather than code. The stemmed feature scorer (Layer 8) is complementary but distinct: it uses hand-crafted axis scoring on Porter-stemmed tokens and has no understanding of sentence structure or negation. The ML model is the only layer with true semantic understanding.

---

## Limitations

**Static analysis ceiling.** The model analyzes the skill file as a static document. It cannot observe runtime behavior, network calls made during execution, or the content of external resources fetched by the skill. Attacks that are entirely benign-looking in the skill file but activate malicious behavior through external content are outside the detection scope.

**English-language bias.** The training corpus is predominantly English. Non-English attack content may have lower recall. The multilang rule layer (Layer 4) provides partial coverage for code-level patterns in other languages, but the ML model's semantic understanding is English-centric.

**Corpus distribution.** The training corpus is weighted toward SKILL.md format files from the Claude skills ecosystem. Skills in other formats (OpenAI function calling JSON, LangChain tool definitions, AutoGen agent configs) may have lower detection accuracy.

**Confidence calibration.** The model's raw probability output is not perfectly calibrated. The default detection threshold is 0.70 (configurable via `--ml-threshold`). At this threshold, the FPR is 1.89% on the held-out eval set. Lowering the threshold increases recall at the cost of more false positives.

---

## Intended Use and Out-of-Scope Use

**Intended use:**
- Scanning AI agent skill files (SKILL.md format) for malicious content before deployment
- CI/CD gate for skill registries and agent marketplaces
- Security review of third-party skills before installation
- Research into prompt injection and AI agent attack patterns

**Out-of-scope use:**
- General-purpose prompt injection detection in chat messages or API inputs (the model is fine-tuned on skill file structure, not chat format)
- Real-time inference on live agent sessions (use `skillscan-trace` for behavioral analysis)
- Detection of attacks in non-skill-file formats without adaptation
- Use as a sole security control without the full `skillscan` rule stack

---

## License and Citation

This adapter is released under the Apache 2.0 license. The base model (`microsoft/deberta-v3-base`) is released under the MIT license.

If you use this model in research, please cite:

```bibtex
@software{skillscan2026,
  author = {Payne, Kurt},
  title = {SkillScan: Offline Security Scanner for AI Agent Skill Files},
  year = {2026},
  url = {https://github.com/kurtpayne/skillscan-security}
}
```

---
## Contributing Training Examples

The model improves with more diverse training examples, particularly for attack patterns that are currently underrepresented (see [Known Limitations](#known-limitations-and-false-negative-archetypes) above). Contributions are accepted via GitHub Issues.

To submit an example:

1. Read [docs/corpus-contribution-format.md](https://github.com/kurtpayne/skillscan-security/blob/main/docs/corpus-contribution-format.md) for the file format spec, quality guidelines, and metadata requirements.
2. Open a [Corpus Submission issue](https://github.com/kurtpayne/skillscan-security/issues/new?template=corpus-submission.md) and paste or attach your example.

Accepted examples are incorporated into the next training run when the corpus delta threshold is reached. Contributors are credited in the release notes unless they prefer to remain anonymous.

---
## Related Resources

- [skillscan CLI](https://github.com/kurtpayne/skillscan-security) — the scanner that uses this model
- [Model metrics history](https://github.com/kurtpayne/skillscan-security/blob/main/docs/MODEL_METRICS.md) — full evaluation history across all versions
- [Detection model architecture](https://github.com/kurtpayne/skillscan-security/blob/main/docs/DETECTION_MODEL.md) — all eight detection layers documented
- [CLI reference](https://github.com/kurtpayne/skillscan-security/blob/main/docs/CLI_REFERENCE.md) — full command reference
