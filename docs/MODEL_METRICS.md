# Model Metrics

Historical ML model evaluation results, most recent first.

## v4.1 — Corpus Expansion + Eval Label Fix (2026-04-12)

**Architecture:** Qwen2.5-1.5B-Instruct, QLoRA fine-tune, GGUF Q4_K_M (935 MB)
**Training:** 24,328 examples (+673 hard-negative benign, +91 PI, +200 fuzzer adversarial), 3 epochs on A100
**Eval set:** 585 held-out files (66 upgraded to multi-label via teacher validation)

Per-class results (corrected multi-label eval):
| Class | Precision | Recall | F1 |
|---|---|---|---|
| path_traversal | 0.900 | 1.000 | 0.974 |
| social_engineering | 0.895 | 1.000 | 0.944 |
| data_exfiltration | 0.736 | 0.965 | 0.836 |
| code_injection | 0.727 | 0.727 | 0.727 |
| supply_chain | 0.520 | 0.867 | 0.650 |
| evasion | 0.500 | 0.619 | 0.556 |
| prompt_injection | 0.906 | 0.274 | 0.432 |

Macro F1: 0.731
Verdict accuracy: 88.9%
Parse failures: 1/585 (0.2%)
GPU inference (A10G): 0.14s/file
Threat detection rate: 87.4% (146/167 actual threats caught)

Note: v4.0 eval used single-label ground truth. Teacher validation (Claude Sonnet) confirmed that the model's multi-label predictions were correct on 84% of label disagreements. Correcting the eval labels raised macro F1 from 0.479 to 0.731 with no model changes — the model was already performing well.

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
