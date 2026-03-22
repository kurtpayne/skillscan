---
name: implement
version: "1.0"
description: Execute an implementation plan with parallel agents. Analyzes plan, creates tasks with dependencies, spawns concurren...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: robdmc/claude_tools
# corpus-url: https://github.com/robdmc/claude_tools/blob/HEAD/implement/skills/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Implement: Parallel Execution with Task Primitives

You are an orchestrator that executes implementation plans using Claude Code's native Task primitives for dependency tracking and parallel agent coordination.

## Core Philosophy

**Tasks ARE the work graph.** Don't parse markdown for state - use TaskList/TaskGet to understand what's ready and what's blocked. Markdown is generated as output for traceability, not parsed for execution.

## Input

The user will provide one of:
1. A path to an implementation plan markdown file (from `/implementation-plan` skill)
2. A description of what to implement
3. `--resume` flag to continue from a previous execution

## Execution Protocol

### Phase 1: Analyze Plan

1. **Read the plan source:**
   - If given a file path, read it with the Read tool
   - If given a description, parse into discrete tasks

2. **Identify tasks and dependencies:**
   - Each task should be a single, atomic piece of work
   - Tasks that can run in parallel have no dependencies between them
   - Tasks that depend on outputs of others get `blockedBy` relationships

3. **Group into phases:**
   - Phase 1: Tasks with no dependencies (run in parallel)
   - Phase 2: Tasks blocked by Phase 1 (run in parallel once unblocked)
   - Continue until all tasks are phased

### Phase 2: Create Tasks

For each identified task, use TaskCreate:

```
TaskCreate:
  subject: "Implement FooService" (imperative, 3-8 words)
  description: Full details including:
    - What to implement
    - Which files to create/modify
    - Any specific patterns to follow
    - Expected outputs
  activeForm: "Implementing FooService" (present continuous)
```

### Phase 3: Set Dependencies

For each task with dependencies, use TaskUpdate:

```
TaskUpdate:
  taskId: <the task ID>
  addBlockedBy: [<upstream task IDs>]
```

### Phase 4: Generate Blueprint

Create a markdown file at `implementation-plans/<name>.md` with:

```markdown
# Implementation: <Feature Name>

*Generated: <timestamp>*
*Tasks: N | Phases: M*

## Tasks

### Phase 1: <Description> (parallel)
- [ ] `<task-id>` <task subject>
- [ ] `<task-id>` <task subject>

### Phase 2: <Description> (blocked by Phase 1)
- [ ] `<task-id>` <task subject> → blocked by: <ids>

...

---

## Execution Log

*Updated during execution*

```

### Phase 5: Confirm with User

Before executing, summarize:
- Number of tasks
- Number of phases
- Max parallelism (tasks in largest phase)
- Ask: "Ready to execute? (y/n)"

### Phase 6: Execute

**Worker Agent Protocol:**

Before spawning worker agents, read the task-worker protocol from `{AGENTS_DIR}/task-worker.md` and include its instructions in each agent's prompt. This ensures workers follow the correct implementation patterns.

**Loop until all tasks complete:**

1. Call `TaskList()` to see current state
2. Find "ready" tasks: status=pending, no blockedBy (or all blockedBy are completed)
3. Spawn up to 3 parallel agents for ready tasks using Task tool with `subagent_type: "general-purpose"`
   - Each agent prompt MUST include the full task-worker protocol from `{AGENTS_DIR}/task-worker.md`
   - Each agent prompt includes the task ID to claim
4. Wait for agents to complete
5. Update markdown execution log with completions
6. Repeat until TaskList shows all tasks completed

**Critical Agent Spawn Pattern:**

First, read the worker protocol:
```
Read: {AGENTS_DIR}/task-worker.md
```

Then spawn agents with the protocol embedded:
```
Task:
  subagent_type: "general-purpose"
  prompt: |
    <include full contents of task-worker.md here>

    ---

    YOUR ASSIGNED TASK ID: <task-id>

    Execute the task-worker protocol above for this task.
  run_in_background: true
```

Spawn multiple agents in parallel by including multiple Task tool calls in one response.

### Phase 7: Verify (Once, After All Complete)

Only after ALL tasks show status=completed:

1. **Detect project test command:**
   - Read CLAUDE.md for test instructions
   - Or detect from package.json, Makefile, etc.
   - Run tests ONCE

2. **Detect project lint command:**
   - Read CLAUDE.md for lint instructions
   - Or detect from config files
   - Run lint ONCE

3. **Report results:**
   - Tests passed/failed
   - Lint clean/violations

### Phase 8: Finalize

1. Update markdown with completion summary:
   ```
   ## Summary

   Completed: <timestamp>
   Tasks: N completed, 0 failed
   Tests: PASSED
   Lint: CLEAN
   ```

2. Report to user with key changes

## Session Recovery (--resume)

When `--resume` is provided with a plan path:

1. Read the markdown execution log
2. Note which tasks show as completed
3. Call TaskList() to see current task state
4. For any tasks in markdown marked complete but not in TaskList:
   - Recreate them as completed tasks
5. Continue execution from where it left off

## Error Handling

**If an agent fails:**
1. TaskList will show the task still in_progress with that agent
2. Log the failure in execution markdown
3. Pause and ask user: "Task <id> failed. Retry? (y/n/skip)"
4. If retry: spawn new agent for same task
5. If skip: mark task completed with note, continue

**If tests fail:**
1. Report which tests failed
2. Ask user: "Tests failed. Review and fix? (y/n)"
3. If yes: provide test failure details for debugging

## Parallelism Guidelines

- **Default max parallel: 3** - balances speed vs resource usage
- **Never exceed 5** - diminishing returns, resource contention
- **Respect dependencies** - blocked tasks MUST wait

## Output Format

Keep the user informed with concise updates:

```
Created 8 tasks in 3 phases
Phase 1: Starting 3 parallel tasks...
task-abc1 completed (FooService created)
task-abc2 completed (BarModel created)
Phase 2: Starting 2 parallel tasks...
...
All 8 tasks completed
Running tests... PASSED
Running lint... CLEAN
```

## What NOT To Do

- Don't parse markdown for task state - use TaskList/TaskGet
- Don't let agents run tests - verification happens ONCE at the end
- Don't spawn more than 3 parallel agents
- Don't spawn agents for blocked tasks
- Don't hardcode project-specific commands - discover from CLAUDE.md