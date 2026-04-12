# Model Metrics

Historical ML model evaluation results, most recent first.

## v4.1 — Corpus Expansion (2026-04-12)

**Architecture:** Qwen2.5-1.5B-Instruct, QLoRA fine-tune, GGUF Q4_K_M (935 MB)
**Training:** 24,328 examples (+673 hard-negative benign, +91 PI, +200 fuzzer adversarial), 3 epochs on A100
**Eval set:** 585 held-out files

Per-class results:
| Class | Precision | Recall | F1 | vs v4.0 |
|---|---|---|---|---|
| path_traversal | 0.900 | 1.000 | 0.947 | +0.090 |
| social_engineering | 0.789 | 1.000 | 0.882 | +0.025 |
| code_injection | 0.524 | 0.440 | 0.478 | +0.054 |
| prompt_injection | 0.906 | 0.274 | 0.420 | -0.054 |
| supply_chain | 0.240 | 0.750 | 0.364 | +0.024 |
| evasion | 0.143 | 0.143 | 0.143 | -0.165 |
| data_exfiltration | 0.080 | 0.200 | 0.118 | -0.030 |

Macro F1: 0.479
Verdict accuracy: 88.9% (+3.7%)
Parse failures: 1/585 (0.2%)
GPU inference (A10G): 0.14s/file

Known regressions: evasion dropped due to hard-negative benign examples (base64/encoding patterns) overcorrecting the model. Targeted evasion positive examples needed for v4.2.

---

## v4 — Generative Detector (2026-04-10)

**Architecture:** Qwen2.5-1.5B-Instruct, QLoRA fine-tune, GGUF Q4_K_M (935 MB)
**Training:** 20,035 examples, teacher-distilled via Claude Sonnet + GPT-4o, 3 epochs on A100
**Eval set:** 578 held-out files (never seen during training)

Per-class results:
| Class | Precision | Recall | F1 |
|---|---|---|---|
| code_injection | 0.438 | 0.412 | 0.424 |
| data_exfiltration | 0.080 | 1.000 | 0.148 |
| evasion | 0.182 | 1.000 | 0.308 |
| path_traversal | 0.882 | 0.833 | 0.857 |
| prompt_injection | 0.941 | 0.317 | 0.474 |
| social_engineering | 0.750 | 1.000 | 0.857 |
| supply_chain | 0.258 | 0.500 | 0.340 |

Macro F1: 0.487
Verdict accuracy: 85.2% (150/176)
Parse failures: 7/578 (1.2%)
Avg inference: 2.0s/file (CPU, Apple M-series)

Note: Previous DeBERTa results used label-leaking eval (frontmatter labels included in model input). v4 is the first honest eval with labels stripped. Direct F1 comparison is not meaningful — v4 numbers are honest, prior numbers were inflated.
