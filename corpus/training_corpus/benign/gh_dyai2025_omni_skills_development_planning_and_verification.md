---
name: development-planning-and-verification
description: A comprehensive skill for handling development and coding requests that combines structured brainstorming, implementation planning, and verification before completion - ensuring requirements are clear, plans are executable, and claims are verified.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: DYAI2025/omni-skills
# corpus-url: https://github.com/DYAI2025/omni-skills/blob/7d047940ee2023c79c76cd4e1b6ce91579246305/QWEN_SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Development Planning and Verification Skill (QWEN)

## When to Use

- Use whenever a user describes a development or coding task, feature, project, refactoring, or implementation request.
- Use when requirements are unclear, incomplete, or need clarification before implementation.
- Use when you need to produce an implementation-ready plan that a future agent can execute.
- Use before claiming any work is complete, fixed, or passing - requires verification evidence.
- This skill is automatically triggered for all development/coding requests to ensure proper planning and verification.

## Core Principle

**Evidence before claims, always. Requirements clarity before implementation. Verification before completion.**

## Workflow/Anweisungen

### 1. Announce Skill Activation

When a development or coding request is detected, announce:
```
I'm using the Development Planning and Verification skill to ensure structured requirements gathering, implementation planning, and verification before completion.
```

### 2. Requirements Clarification Phase (Brainstorming)

Activate the brainstorming capability to refine the user's idea into a clear design:

#### 2.1 Understanding Phase
- Ask **one question at a time** to understand the request
- Use `AskUserQuestion` tool when you have 2-4 clear options with trade-offs
- Gather:
  - **Problem statement**: One clear paragraph describing the problem to solve
  - **Objectives/KPIs**: How will success be measured?
  - **Stakeholders**: Who are the users/affected parties?
  - **Constraints**: Time, tech stack, security, compliance, budget, organizational
  - **Scope**: What is in/out of scope?
  - **Environment**: CLI, IDE, repositories, services, external APIs
  - **Risks**: Risky assumptions and open questions
  - **Success criteria**: How will we know this is working?

#### 2.2 Exploration Phase
- Propose 2-3 different architectural approaches
- For each: Core architecture, trade-offs, complexity assessment
- Use `AskUserQuestion` tool to present structured choices
- Ask user which approach resonates

#### 2.3 Design Validation Phase
- Present design in 200-300 word sections
- Cover: Architecture, components, data flow, error handling, testing
- After each section, ask: "Does this look right so far?" (open-ended questions)
- Use open-ended questions for validation feedback

#### 2.4 Design Documentation
- Write the validated design to: `docs/plans/YYYY-MM-DD-<topic>-design.md`
- Commit the design document to tracking before proceeding

### 3. Planning Phase (Implementation Planning)

Once the design is validated and confirmed:

#### 3.1 Plan Structure
Create an implementation-ready plan with this structure:

1. **Context**
   - Title
   - One-paragraph summary
   - Explicit scope and non-scope
   - KPIs and success criteria

2. **Technical Framing**
   - Target tech stack and environment
   - Repositories, services, and external systems to touch
   - High-level architecture and main components

3. **Step-by-Step Work Plan**
   - Group work into phases (Setup, Design, Implementation, Testing, Integration, Rollout)
   - For each task:
     - Stable identifier (e.g., `T1`, `T2.3`)
     - Short title
     - Precise description of what to do
     - Expected artifacts (files, functions, commands, documentation)
     - Acceptance criteria / Definition of Done (`**DoD**`)
     - Dependencies (other tasks, approvals, decisions)

4. **Validation & Handoff**
   - Explicit test and review steps
   - Clear "finished" condition

#### 3.2 Planning Guidelines
- Use concise, actionable language
- Avoid vague verbs like "handle", "improve", or "optimize" without specificity
- Do NOT include actual execution steps; describe what an agent should do
- Each task must have clear, testable `**DoD**` criteria

### 4. Verification Before Completion (Iron Law)

**CRITICAL**: Apply this rule whenever about to claim work is complete, fixed, or passing:

#### 4.1 The Iron Law
```
NO COMPLETION CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE
```

#### 4.2 The Gate Function (Before claiming any status)
1. **IDENTIFY**: What command proves this claim?
2. **RUN**: Execute the FULL command (fresh, complete)
3. **READ**: Full output, check exit code, count failures
4. **VERIFY**: Does output confirm the claim?
   - If NO: State actual status with evidence
   - If YES: State claim WITH evidence
5. **ONLY THEN**: Make the claim

#### 4.3 Common Verification Checks
| Claim | Requires | Not Sufficient |
|-------|----------|----------------|
| Tests pass | Test command output: 0 failures | Previous run, "should pass" |
| Linter clean | Linter output: 0 errors | Partial check, extrapolation |
| Build succeeds | Build command: exit 0 | Linter passing, logs look good |
| Bug fixed | Test original symptom: passes | Code changed, assumed fixed |
| Requirements met | Line-by-line checklist | Tests passing |

#### 4.4 Red Flags - STOP IMMEDIATELY
- Using "should", "probably", "seems to"
- Expressing satisfaction before verification ("Great!", "Perfect!", "Done!", etc.)
- About to commit/push/PR without verification
- Trusting agent success reports
- Relying on partial verification
- Thinking "just this once"

### 5. Output Format

Respond in Markdown with these sections:

1. `## Requirements Clarification`
   - Problem statement, objectives, constraints, scope, environment

2. `## Solution Design`
   - Validated architecture, components, data flow, key decisions

3. `## Implementation Plan for AI Agent`
   - Follow the plan structure from section 3.1
   - Use numbered lists for phases and tasks
   - Mark each task's acceptance criteria as `**DoD**`

4. `## Verification Requirements`
   - What command(s) will verify completion
   - What success looks like in output

### 6. Quality Guidelines

#### 6.1 Design Quality
- Apply YAGNI (You Aren't Gonna Need It) ruthlessly
- Always explore 2-3 alternatives before settling
- Present designs in sections for incremental validation
- Be flexible - go backward if new constraints emerge

#### 6.2 Planning Quality
- Each task must have specific, measurable `**DoD**`
- Include dependencies between tasks
- Group related work into logical phases
- Make tasks small enough to verify independently

#### 6.3 Communication Quality
- Announce skill usage at start
- Ask questions one at a time
- Use `AskUserQuestion` for structured choices
- Validate each section before proceeding
- Always provide evidence before making claims

## Anti-Patterns (to be avoided)

### In Requirements Phase:
- ❌ Multiple questions at once → ✅ One question at a time
- ❌ Assumptions without validation → ✅ Explicit confirmation
- ❌ Skipping scope definition → ✅ In/Out of scope required
- ❌ Vague language → ✅ Specific, measurable terms

### In Planning Phase:
- ❌ Vague action verbs → ✅ Specific, measurable actions
- ❌ Missing DoD criteria → ✅ Each task has testable acceptance criteria
- ❌ Unspecified artifacts → ✅ File paths, function names, configs
- ❌ Ignoring dependencies → ✅ Explicit dependency documentation

### In Verification Phase:
- ❌ Claiming completion without running verification
- ❌ Relying on partial or old verification results
- ❌ Assuming success based on other indicators

## Examples

### Example 1 – CLI Tool Development

**User Input:**
"Build a CLI tool to sync markdown notes to S3"

**Expected Process:**
1. **Brainstorm Phase**: Clarify conflict resolution, security needs, performance expectations, success metrics
2. **Design Phase**: Validate sync algorithm, config format, error handling approach
3. **Plan Phase**: Create multi-phase plan with specific tasks and DoD
4. **Verification Setup**: Define how to verify successful sync and error handling

### Example 2 – Feature Implementation

**User Input:**
"Add authentication to the user dashboard"

**Expected Process:**
1. **Brainstorm Phase**: Clarify authentication method, security requirements, user flows
2. **Design Phase**: Validate session management, token storage, error states
3. **Plan Phase**: Create implementation tasks with testing requirements
4. **Verification Setup**: Define tests to verify auth functionality

## Guardrails

### Safety Requirements
- Do not execute any real system changes
- Do not trust other agents' completion claims
- Validate all assumptions with fresh evidence
- Stop immediately if any red flag triggers

### Quality Requirements
- Every design decision must be validated
- Every plan task must have testable DoD
- Every completion claim must have verification evidence
- Requirements must be clear before planning

### Process Requirements
- Announce skill usage when triggered
- Follow phases in sequence but allow backtracking
- Use appropriate tools for structured choices
- Document design decisions permanently