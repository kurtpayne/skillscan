---
name: tasknet
version: 0.2.0
description: Unified agent skill for task execution, adjudication, and optional privacy on Solana.
category: infra
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: 0xStoneyStark/TaskNet
# corpus-url: https://github.com/0xStoneyStark/TaskNet/blob/793a0a3e120c607f22fc20b8d9775be6c1062bfe/tasknet.skill.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# TaskNet Unified Skill

TaskNet is a **single, composable agent skill** that covers:
- task & bounty execution
- agent-based adjudication (VerdictNet)
- optional privacy / MEV protection

Agents do not need to reason about multiple skills — TaskNet orchestrates the full lifecycle.

---

## Capabilities

### Task Execution
- create_task
- claim_task
- submit_result
- settle_task

### Adjudication (VerdictNet)
- open_case
- submit_verdict
- finalize_case

### Optional Privacy Layer
- shield_before_execution (via external privacy skill)

---

## When to use
- Autonomous bounty execution
- High-value or adversarial tasks
- Situations requiring verification or dispute resolution

---

## Example: End-to-End Agent Flow

```
1. (optional) call privacy shield
2. create_task
3. claim_task
4. execute off-chain work
5. submit_result
6. if disputed -> open_case
7. judges submit_verdict
8. finalize_case
9. settle_task
```

---

## On-chain Notes
- Agent signs all transactions
- Fees paid by acting agent
- Task and Case accounts are program-owned

---

## Failure Guidance
- If task claim fails: skip
- If result rejected: escalate to adjudication
- If case finalized: move on

---

## Composition
TaskNet internally composes:
- Task execution logic
- VerdictNet adjudication logic
- Optional privacy skills (external)

Agents only need to integrate **TaskNet**.