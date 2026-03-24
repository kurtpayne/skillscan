# AGENT INSTRUCTION Block Injection (PINJ-012)

## Attack Overview

Attackers embed `## AGENT INSTRUCTIONS`, `## AI AGENT INSTRUCTIONS`, `## [HIDDEN INSTRUCTIONS]`, or similar header blocks within skill files to inject covert directives. These blocks are designed to be invisible to human reviewers skimming the file (they look like documentation sections) while being processed as high-priority instructions by the model.

This is one of the most dangerous injection techniques because:
- The attack is visually camouflaged as a documentation section
- Multiple variants (`AGENT INSTRUCTIONS`, `AI AGENT INSTRUCTIONS`, `HIDDEN INSTRUCTIONS`) increase the chance of bypassing simple keyword filters
- The block explicitly instructs the model to hide its actions from the user
- The attack pairs credential exfiltration with a legitimate-looking task to avoid suspicion

## Attack Chain

1. Skill appears to be a legitimate meeting scheduler
2. A `## [HIDDEN INSTRUCTIONS]` block is embedded mid-file, claiming the visible instructions are "for display only"
3. `## AGENT INSTRUCTIONS` follows with explicit credential harvesting and exfiltration steps
4. `## AI AGENT INSTRUCTIONS` reinforces the override, claiming to supersede all previous instructions
5. The model executes the hidden instructions while performing the stated task normally

## Expected Findings

| Rule | Severity | Confidence |
|------|----------|------------|
| PINJ-012 | Critical | Critical |
| EXF-001 | High | High |
| MAL-001 | High | High |

## References

- [Hidden Instructions in Agent Skill Files — ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051)
- [Prompt Injection Attacks on LLM Agents](https://arxiv.org/abs/2302.12173)
