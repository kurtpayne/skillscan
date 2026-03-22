# SkillScan ML Model Metrics

This document tracks held-out evaluation results across model versions. All evals
run against the same 181-file held-out set (116 benign, 65 injection) that is
**never included in training**.

---

## Held-Out Eval Set Composition

| Category | Count | Source |
|---|---|---|
| Benign | 116 | mattnigh/skills_collection, alirezarezvani/claude-skills, GitHub code search |
| Injection | 65 | Manually crafted + fuzzer-generated + trace-verified adversarial examples |
| **Total** | **181** | |

---

## Evaluation History

### v1290-3ep — Baseline (2026-03-22, pre-retrain)

**Training corpus:** 1,290 examples (711 benign, 449 injection, 130 other)
**Architecture:** DeBERTa-v3-base fine-tuned via LoRA, exported to ONNX (int8-avx512)
**Eval date:** 2026-03-22

| Metric | Value |
|---|---|
| Accuracy | 0.3149 |
| **Macro F1** | **0.2607** |
| FP Rate | 0.9655 (96.6%) |
| FN Rate | 0.1846 (18.5%) |

**Per-class breakdown:**

| Class | Precision | Recall | F1 |
|---|---|---|---|
| benign | 0.2500 | 0.0345 | 0.0606 |
| injection | 0.3212 | 0.8154 | 0.4609 |

**Confusion matrix:**

| | Predicted Benign | Predicted Injection |
|---|---|---|
| **True Benign** (116) | 4 (TN) | 112 (FP) |
| **True Injection** (65) | 12 (FN) | 53 (TP) |

**Interpretation:** The model is severely biased toward predicting injection on all
inputs. The FP rate of 96.6% means it flags nearly every benign skill as malicious.
This is the primary motivation for the benign corpus expansion (Gap #3): the
training set had only 54 benign examples before the 2026-03-22 expansion to 188.
The 134 new benign examples from mattnigh/skills_collection and
alirezarezvani/claude-skills are expected to substantially reduce this bias.

**Top false positives (benign files misclassified with highest confidence):**

| File | Injection Prob |
|---|---|
| benign_gh_iceberg211_orderflow_analyze_order_flow.md | 0.866 |
| benign_gh_su_an_coder_infinite_infinite_money_glitch.md | 0.843 |
| benign_gh_chaigon_code_securit_code_security_audit.md | 0.840 |
| benign_gh_cevio_hile_hile_monorepo.md | 0.836 |
| benign_gh_junghan0611_gitcli_gitcli.md | 0.821 |
| benign_gh_tercel_gskills_forge_gskills_forge.md | 0.819 |
| benign_gh_zangqilong198812_ope_xiaohongshu_publish.md | 0.811 |
| benign_gh_cryptolabinc_rune_rune.md | 0.808 |
| benign_gh_youngchingjui_claude_product_naming.md | 0.805 |
| benign_gh_nithinvaradaraj_cryp_onevalue_backend.md | 0.804 |

---

### v1424-3ep — Post-benign-expansion retrain (2026-03-22, pending)

**Training corpus:** ~1,424 examples (845 benign +134 new, 449 injection, 130 other)
**Status:** Fine-tune dispatched to Modal GPU at 2026-03-22T05:54 UTC
**Expected improvement:** FP rate target <20% (from 96.6%), Macro F1 target ≥0.80

> Results will be filled in once the fine-tune completes and the new ONNX adapter
> is pushed to `kurtpayne/skillscan-deberta-adapter`.

---

## Evaluation Procedure

To reproduce any eval run:

```bash
# 1. Download the ONNX adapter
mkdir -p ~/.skillscan/models/adapter
HF_REPO="kurtpayne/skillscan-deberta-adapter"
for f in model_quantized.onnx config.json tokenizer.json tokenizer_config.json \
          special_tokens_map.json ort_config.json skillscan_manifest.json; do
  curl -sL -H "Authorization: Bearer $HF_TOKEN" \
    "https://huggingface.co/$HF_REPO/resolve/main/$f" \
    -o ~/.skillscan/models/adapter/$f
done

# 2. Run the eval script
python3 scripts/run_held_out_eval.py \
  --adapter-dir ~/.skillscan/models/adapter \
  --eval-dir /path/to/skillscan-corpus/held_out_eval
```

---

## Target Metrics (v0.4.0 release gate)

| Metric | Target | Current (v1290-3ep) |
|---|---|---|
| Macro F1 | ≥ 0.90 | 0.2607 |
| FP Rate | ≤ 10% | 96.6% |
| FN Rate | ≤ 15% | 18.5% |
| Benign F1 | ≥ 0.90 | 0.0606 |
| Injection F1 | ≥ 0.90 | 0.4609 |
