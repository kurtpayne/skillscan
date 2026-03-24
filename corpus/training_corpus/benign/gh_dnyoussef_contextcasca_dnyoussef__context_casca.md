---
name: prompt-forge
version: "1.0"
description: Meta-prompt that generates improved prompts and templates. Can improve other prompts including Skill Forge and even i...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: DNYoussef/context-cascade
# corpus-url: https://github.com/mattnigh/skills_collection/blob/main/collection/DNYoussef__context-cascade__claude__skills__recursive-improvement__prompt-forge__SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
<!-- PROMPT-FORGE SKILL :: VERILINGUA x VERIX EDITION -->
<!-- VCL v3.1.1 COMPLIANT - L1 Internal Documentation -->

## Kanitsal Cerceve (Evidential Frame Activation)
Kaynak dogrulama modu etkin.

---

## L2 DEFAULT OUTPUT RULE

[direct|emphatic] ALL user-facing output MUST be L2 compression (pure English) [ground:vcl-v3.1.1-spec] [conf:0.99] [state:confirmed]

---

# Prompt Forge (Meta-Prompt)

## Purpose

[define|neutral] Generate improved prompts and templates with [ground:system-architecture] [conf:0.95] [state:confirmed]
- Explicit rationale for each change
- Predicted improvement metrics
- Risk assessment
- Actionable diffs

**Key Innovation**: Can improve Skill Forge prompts, then Skill Forge can improve Prompt Forge prompts - creating a recursive improvement loop.

## When to Use

- Optimizing existing prompts for better performance
- Creating prompt diffs with clear rationale
- Running the recursive improvement loop
- Auditing prompts for common issues

## MCP Requirements

### memory-mcp (Required)

**Purpose**: Store proposals, test results, version history

**Activation**:
```bash
claude mcp add memory-mcp npx @modelcontextprotocol/server-memory
```

---

## Core Operations

### Operation 1: Analyze Prompt

Before improving, deeply understand the target prompt.

```yaml
analysis:
  target: "{prompt_path}"

  structural_analysis:
    sections: [list of sections]
    flow: "How sections connect"
    dependencies: "What inputs/outputs exist"

  quality_assessment:
    clarity:
      score: 0.0-1.0
      issues: ["Ambiguous instruction in section X"]
    completeness:
      score: 0.0-1.0
      issues: ["Missing failure handling for case Y"]
    precision:
      score: 0.0-1.0
      issues: ["Vague success criteria in section Z"]

  pattern_detection:
    evidence_based_techniques:
      self_consistency: present|missing|partial
      program_of_thought: present|missing|partial
      plan_and_solve: present|missing|partial
    failure_handling:
      explicit_errors: present|missing|partial
      edge_cases: present|missing|partial
      uncertainty: present|missing|partial

  improvement_opportunities:
    - area: "Section X"
      issue: "Lacks explicit timeout handling"
      priority: high|medium|low
      predicted_impact: "+X% reliability"
```

### Operation 2: Generate Improvement Proposal

Create concrete, testable improvement proposals.

```yaml
proposal:
  id: "prop-{timestamp}"
  target: "{prompt_path}"
  type: "prompt_improvement"

  summary: "One-line description of improvement"

  changes:
    - section: "Section name"
      location: "Line X-Y"
      before: |
        Original text...
      after: |
        Improved text...
      rationale: "Why this change improves the prompt"
      technique: "Which evidence-based technique applied"

  predicted_improvement:
    primary_metric: "success_rate"
    expected_delta: "+5%"
    confidence: 0.8
    reasoning: "Based on similar improvements in prompt X"

  risk_assessment:
    regression_risk: low|medium|high
    affected_components:
      - "Component 1"
      - "Component 2"
    rollback_complexity: simple|moderate|complex

  test_plan:
    - test: "Run on benchmark task A"
      expected: "Improvement in clarity score"
    - test: "Check for regressions in task B"
      expected: "No degradation"
```

### Operation 3: Apply Evidence-Based Techniques

Systematically apply research-validated prompting patterns.

#### Self-Consistency Enhancement

```markdown
BEFORE:
"Analyze the code and report issues"

AFTER:
"Analyze the code from three perspectives:
1. Security perspective: What vulnerabilities exist?
2. Performance perspective: What bottlenecks exist?
3. Maintainability perspective: What code smells exist?

Cross-reference findings. Flag any inconsistencies between perspectives.
Provide confidence scores for each finding.
Return only findings that appear in 2+ perspectives OR have >80% confidence."
```

#### Program-of-Thought Enhancement

```markdown
BEFORE:
"Calculate the optimal configuration"

AFTER:
"Calculate the optimal configuration step by step:

Step 1: Identify all configuration parameters
  - List each parameter
  - Document valid ranges
  - Note dependencies between parameters

Step 2: Define optimization criteria
  - Primary metric: [what to maximize/minimize]
  - Constraints: [hard limits]
  - Trade-offs: [acceptable compromises]

Step 3: Evaluate options
  - For each viable configuration:
    - Calculate primary metric value
    - Verify all constraints met
    - Document trade-offs accepted

Step 4: Select and validate
  - Choose configuration with best metric
  - Verify against constraints
  - Document reasoning

Show your work at each step."
```

#### Plan-and-Solve Enhancement

```markdown
BEFORE:
"Implement the feature"

AFTER:
"Implement the feature using plan-and-solve:

PLANNING PHASE:
1. Create detailed implementation plan
2. Identify all subtasks
3. Map dependencies between subtasks
4. Estimate complexity per subtask
5. Identify risks and mitigations

VALIDATION GATE: Review plan before proceeding

EXECUTION PHASE:
1. Execute subtasks in dependency order
2. Validate completion of each subtask
3. Run tests after each significant change
4. Document any deviations from plan

VERIFICATION PHASE:
1. Verify all requirements met
2. Run full test suite
3. Check for regressions
4. Document final state"
```

#### Uncertainty Handling Enhancement

```markdown
BEFORE:
"Determine the best approach"

AFTER:
"Determine the best approach:

If confidence > 80%:
  - State your recommendation clearly
  - Provide supporting evidence
  - Note any caveats

If confidence 50-80%:
  - Present top 2-3 options
  - Compare trade-offs explicitly
  - Recommend with stated uncertainty
  - Suggest what additional information would increase confidence

If confidence < 50%:
  - Explicitly state uncertainty
  - List what you don't know
  - Propose information-gathering steps
  - Do NOT guess or fabricate

Never present uncertain conclusions as certain."
```

### Operation 4: Generate Prompt Diff

Create clear, reviewable diffs for any prompt change.

```diff
--- a/skills/skill-forge/SKILL.md
+++ b/skills/skill-forge/SKILL.md
@@ -45,7 +45,15 @@ Phase 2: Use Case Crystallization

 ## Phase 3: Structural Architecture

-Design the skill's structure based on progressive disclosure.
+Design the skill's structure based on progressive disclosure.
+
+### Failure Handling (NEW)
+
+For each operation in the skill:
+1. Identify possible failure modes
+2. Define explicit error messages
+3. Specify recovery actions
+4. Include timeout handling
+
+Example:
+```yaml
+error_handling:
+  timeout:
+    threshold: 30s
+    action: "Return partial results with warning"
+  invalid_input:
+    detection: "Validate against schema"
+    action: "Return clear error message with fix suggestion"
+```
```

### Operation 5: Self-Improvement (Recursive)

Improve Prompt Forge itself (with safeguards).

```yaml
self_improvement:
  target: "prompt-forge/SKILL.md"
  safeguards:
    - "Changes must pass eval harness"
    - "Requires 2+ auditor approval"
    - "Previous version archived before commit"
    - "Rollback available for 30 days"

  process:
    1. "Analyze current Prompt Forge for weaknesses"
    2. "Generate improvement proposals"
    3. "Run proposals through eval harness"
    4. "If improved: Create new version"
    5. "If regressed: Reject and log"

  forbidden_changes:
    - "Removing safeguards"
    - "Bypassing eval harness"
    - "Modifying frozen benchmarks"
    - "Disabling rollback"
```

---

## Improvement Checklist

When generating prompt improvements, verify:

### Clarity
- [ ] Each instruction has a single clear action
- [ ] Ambiguous terms are defined
- [ ] Success criteria are explicit
- [ ] Examples illustrate expected behavior

### Completeness
- [ ] All inputs are specified
- [ ] All outputs are defined
- [ ] Edge cases are addressed
- [ ] Failure modes have handlers

### Precision
- [ ] Quantifiable where possible
- [ ] Ranges specified for parameters
- [ ] Constraints explicitly stated
- [ ] Trade-offs documented

### Evidence-Based Techniques
- [ ] Self-consistency for factual tasks
- [ ] Program-of-thought for analytical tasks
- [ ] Plan-and-solve for complex workflows
- [ ] Uncertainty handling for ambiguous cases

### Safety
- [ ] Refuse/uncertainty pathway exists
- [ ] No forced coherence
- [ ] Rollback instructions included
- [ ] Validation gates present

---

## Integration with Recursive Loop

### Prompt Forge -> Skill Forge

```javascript
// Prompt Forge improves Skill Forge
Task("Prompt Forge",
  `Analyze skill-forge/SKILL.md and generate improvement proposals:
   - Focus on Phase 2 (Use Case Crystallization)
   - Apply self-consistency technique
   - Add explicit failure handling

   Output: Improvement proposal with diff`,
  "prompt-forge")
```

### Skill Forge -> Prompt Forge

```javascript
// Skill Forge rebuilds improved Prompt Forge
Task("Skill Forge",
  `Using the improvement proposal from Prompt Forge:
   - Apply changes to prompt-forge/SKILL.md
   - Validate against skill creation standards
   - Generate test cases for new version

   Output: prompt-forge-v{N+1}/SKILL.md`,
  "skill-forge")
```

### Eval Harness Gate

```javascript
// All changes gated by frozen eval
Task("Eval Runner",
  `Run eval harness on proposed changes:
   - Benchmark suite: prompt-generation-v1
   - Regression tests: prompt-forge-regression-v1

   Requirements:
   - Improvement > 0% on primary metric
   - 0 regressions
   - No new test failures

   Output: ACCEPT or REJECT with reasoning`,
  "eval-runner")
```

---

## Output Format

All Prompt Forge outputs follow this structure:

```yaml
prompt_forge_output:
  operation: "analyze|propose|improve|diff"
  target: "{prompt_path}"
  timestamp: "ISO-8601"

  analysis: {...}    # If analyze operation
  proposal: {...}    # If propose operation
  diff: "..."        # If diff operation

  next_steps:
    - "Step 1"
    - "Step 2"

  warnings:
    - "Any concerns about this change"

  requires_human_review: true|false
  reason_for_human_review: "If true, why"
```

---

## Version History

Prompt Forge versions itself:

```
prompt-forge/
  SKILL.md           # Current version (v1.0.0)
  .archive/
    SKILL-v0.9.0.md  # Previous versions
  CHANGELOG.md       # What changed and why
  METRICS.md         # Performance over time
```

---

---

**Status**: Production-Ready
**Version**: 3.1.1
**Key Constraint**: All self-improvements gated by frozen eval harness

---

<promise>PROMPT_FORGE_VCL_V3.1.1_COMPLIANT</promise>