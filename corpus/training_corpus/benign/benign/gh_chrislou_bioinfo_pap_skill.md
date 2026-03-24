---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: ChrisLou-bioinfo/Paper2Protocol
# corpus-url: https://github.com/ChrisLou-bioinfo/Paper2Protocol/blob/8a8c665f43386a17c54695ac3d36ffd370fb4608/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# SKILL.md — Paper2Protocol Skill Definition

**Version:** 1.2
**Created:** 2026-03-20
**License:** CC BY-NC 4.0

## Overview

From published high-impact primary literature, reverse-engineer complete experimental validation plans — transforming scientific discoveries into executable research protocols.

**Core Principle: Only use primary sources (PMC full-text, journal PDFs), never abstracts or second-hand reviews.**

---

## Input Requirements

### ✅ Accepted
- PMC full-text (NCBI PubMed Central, Open Access)
- Journal website PDFs (Nature/Science/Cell, peer-reviewed)
- DeepReader-generated full-text analysis documents

### ❌ Rejected
- Abstracts only
- News articles / media interpretations
- Review articles (as primary input)
- AI-generated summaries (not based on primary sources)

### Input Formats
1. **PMC URL** → Auto-fetch full text
2. **PDF file** → Direct analysis
3. **Paper title** → Search PMC for full text

---

## Workflow (5 Stages)

### Stage 1: Source Acquisition & Quality Assessment

1. Validate input as primary source
2. Fetch full text (PMC API / PDF parsing)
3. Quality rating:
   - Journal tier (CNS / sub-journal / field-top / other)
   - Research type (basic / clinical / translational)
   - Data completeness (supplementary materials, raw data links)
   - Reproducibility (method detail, sample size)

### Stage 2: Scientific Logic Deconstruction

Extract complete scientific logic:

1. **Core Scientific Question**: What problem does this paper solve?
2. **Research Strategy**: Hypothesis, models (in vivo/in vitro/in silico/clinical), key techniques
3. **Validation Chain**:
   ```
   Hypothesis → Key Experiment 1 → Key Experiment 2 → ... → Conclusion
   ```
   Annotate purpose and expected outcome at each node.
4. **Innovation Analysis**: Methodological, conceptual, and application innovations.

### Stage 3: Executable Experimental Paths

#### 3.1 Experiment Layering
- **Must-do**: Core experiments validating the hypothesis
- **Should-do**: Supporting experiments
- **Nice-to-do**: Mechanism deep-dives or scope extensions

#### 3.2 Per-Experiment Details

| Field | Content |
|-------|---------|
| Experiment Name | Specific name |
| Purpose | Role in validation chain |
| Method | Detailed protocol (paper Methods + best practices) |
| Samples/Materials | Cell lines, animal models, clinical samples |
| Sample Size | Statistically required minimum |
| Key Reagents | Brand, catalog reference, concentration |
| Equipment | Required instruments + alternatives |
| Expected Results | Positive/negative controls, data type |
| Timeline | Per-experiment duration + replicates |
| Budget | Reagents + consumables + services |
| Risk Assessment | Failure causes + backup plans |

#### 3.3 Bioinformatics Analysis (if applicable)

| Field | Content |
|-------|---------|
| Analysis Goal | Specific task |
| Data Source | Public databases (TCGA/GEO) or generated data |
| Tools | Recommended pipeline (R/Python/online) |
| Key Parameters | Standard settings |
| Expected Output | Figure types, statistics |
| Compute Resources | Local/server/cloud requirements |

#### 3.4 Bioinformatics Code (REQUIRED when analysis involves bioinformatics)

**When experiments involve bioinformatics, complete runnable code MUST be provided.**

Requirements:
- **Language**: R (Bioconductor) or Python (R preferred)
- **Completeness**: End-to-end, data download to publication figures
- **Comments**: Key steps annotated in English
- **Data Sources**: Prioritize public databases (TCGA, GEO, Beat-AML)
- **Standard Tools**: ssGSEA/GSEA, DESeq2, CIBERSORTx/xCell, survival, ComplexHeatmap
- **Statistical Rigor**: Multiple testing correction (BH), power analysis

Coverage:
1. **Subtype Classification**: ssGSEA + K-means/Hierarchical clustering
2. **Differential Expression**: DESeq2/edgeR → volcano plot
3. **Survival Analysis**: Kaplan-Meier + Cox regression + ROC (timeROC)
4. **Gene Enrichment**: GSEA + ssGSEA + Hallmark/Immunologic gene sets
5. **Immune Microenvironment**: CIBERSORTx/xCell deconvolution
6. **Heatmaps**: ComplexHeatmap / pheatmap
7. **Prognostic Models**: LASSO Cox + glmnet + Nomogram (rms)
8. **Flow Cytometry**: FlowJo export → Python statistical analysis
9. **Panel Selection**: LASSO + Random Forest intersection → minimal gene set
10. **Automation**: Bash shell script to chain all analysis steps

#### 3.5 Budget Summary

```
Phase 1 (Core Validation): $XX,XXX
  - Reagents: $X,XXX
  - Consumables: $X,XXX
  - Services (sequencing): $XX,XXX
  - Animals: $X,XXX

Phase 2 (Mechanism): $XX,XXX
...

Total: $XXX,XXX – $XXX,XXX
```

### Stage 4: Extension Projects (2-3 proposals)

Each includes:
- **Project Name**
- **Scientific Question**
- **Innovation** vs original paper
- **Feasibility**: ⭐ rating (technical difficulty, resources, timeline)
- **Expected Outcomes**: Paper tier, patent potential, clinical value
- **Risk Assessment**: Bottlenecks and failure risks

### Stage 5: Multi-Paper Synthesis (Accumulation Mode)

Triggered when ≥3 papers accumulate per topic:

- **By Scientific Question**: Group papers by shared research questions
- **By Method**: Rank techniques by frequency → prioritize platform setup
- **Integrated Roadmap**: Deduplicate protocols, consolidate budgets
- **Research Timeline**: 12-month plan based on synthesis

---

## Output Format

### Standard Structure

```markdown
# 📋 [Paper Title] → Experimental Validation Plan

## 📄 Paper Information
## 🔬 Part 1: Validation Logic
## 🧪 Part 2: Executable Experimental Paths
## 💻 Part 3: Bioinformatics Code (if applicable)
## 🚀 Part 4: Extension Projects
## 📝 Execution Recommendations
```

### Output Formats
- **Markdown** (default)
- **PDF Report** (HTML → browser print, all tables and code blocks)
- **Any document platform** (Feishu, Notion, etc.)

---

## Storage & Indexing

```
literature-to-experiment/
├─ index.json
├─ by_project/
│  └─ [Project Name]/
│     └─ PMCxxxxxx_protocol.md
├─ by_topic/
│  └─ [Topic Name]/
└─ summaries/
   └─ [Topic]_synthesis.md
```

---

## Notes

1. **Pricing**: Based on 2025-2026 market rates, marked "reference price"
2. **Sample Size**: Follows statistical principles, power analysis recommended
3. **Ethics**: Mark IRB/IACUC requirements for human/animal studies
4. **Timeliness**: Flag methods >5 years old for verification
5. **Code**: Must provide complete runnable code for bioinformatics analyses

---

## Dependencies

- **DeepReader**: Full-text analysis (pre-requisite step)
- **academic-paper**: If integrating plans into papers

## License

CC BY-NC 4.0 — Free for academic use with attribution. No commercial use without permission.

## Authors

- Jiacheng Lou ([GitHub](https://github.com/ChrisLou-bioinfo))
- 🦞 Claw (AI Research Assistant)