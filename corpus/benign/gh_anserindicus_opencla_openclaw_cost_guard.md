---
name: openclaw-cost-guard
description: reduce openclaw token and money waste by inspecting context growth, tool overhead, skill overhead, cache pressure, and likely high-cost patterns. use when the user asks for a cost check, asks to lower cost, asks where cost was saved, or when the run shows long context, many tools, large tool outputs, high estimated cost, repeated waste, or a need to attribute savings by cause. provide concise diagnostics, low-risk savings actions, permission-aware automation, savings attribution, and a short report with token and money impact for the current turn and the cumulative session.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: anserIndicus/openclaw-cost-guard
# corpus-url: https://github.com/anserIndicus/openclaw-cost-guard/blob/41a7a9b9c9dd218b5df308b19ec7e08c3a8c5c41/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# OpenClaw Cost Guard

## Overview

Detect token waste early, classify actions by risk, and help the user reduce cost without breaking useful work. Prefer a short diagnosis, a small number of high-leverage actions, and a concise savings report. When savings were achieved, attribute them conservatively so the user can see what actually saved money.

## Core workflow

Follow this sequence:

1. Inspect the current run and session.
2. Identify the biggest cost drivers.
3. Separate low-risk actions from high-risk actions.
4. Check the user's low-risk automation permission state.
5. Either recommend actions or execute approved low-risk actions.
6. Re-measure and report savings for this turn and for the session so far.
7. Attribute the savings to concrete causes and label anything inferred or estimated.

## Inspect first

Use any readable signals that are available, including:

- `/status`
- `/usage tokens` or `/usage full`
- `/usage cost`
- `/context list`
- `/context detail`
- current model and pricing configuration
- recent tool calls and tool results
- current session history length and compaction status

Focus on these contributors in order:

1. conversation history growth
2. tool result size and repeated tool output replay
3. tool schema overhead
4. injected workspace files and bootstrap content
5. skill list overhead
6. attachments and screenshot detail
7. cache ttl expiry and re-caching
8. model choice mismatched to task value

## Trigger conditions

Trigger this skill when either of these is true:

- the user explicitly asks for a cost check, asks to lower cost, or asks where savings came from
- the run appears expensive or wasteful, such as long context, many tools, large tool outputs, repeated reads, high estimated cost, or obvious overuse of a premium model

When the trigger is implicit, say briefly why you are intervening.

## Permission model

Read `references/authorization-state.md` before deciding whether to auto-execute low-risk actions.

Treat the permission states as:

- `undeclared`: ask once whether low-risk actions may be auto-executed in future runs
- `allowed`: auto-execute low-risk actions when they clearly reduce cost without changing persistent configuration or task intent
- `refused`: do not auto-execute low-risk actions; only recommend them

If the user grants or revokes permission, update `references/authorization-state.md` with `scripts/set_authorization_state.py` when write access is available. If the skill files are read-only, explicitly say the state could not be persisted and continue with the session-level state only.

## Low-risk actions

Low-risk actions are reversible, session-scoped, and should not materially change the user's intended outcome.

Approved low-risk actions include:

- compacting an overgrown session
- preferring summaries, diffs, top-n rows, or filtered excerpts over raw dumps
- avoiding duplicate file reads and repeated context inspection within the same diagnosis
- avoiding unnecessary skill or reference reads
- asking tools for smaller outputs in the current run
- switching the response style to concise when the user did not ask for detail
- proposing a smaller model for the next step, but only auto-switching if the environment explicitly supports session-only model changes and the user has already allowed low-risk automation

Do not classify these as low-risk if they would edit persistent configuration or could hide information the user explicitly asked to see.

## High-risk actions

Always ask before high-risk actions.

High-risk actions include:

- editing config files
- changing persistent agent defaults
- changing model pricing configuration
- changing cache retention, heartbeat, pruning, or bootstrap limits in config
- changing skill metadata, tool exposure, or other shared workspace settings
- deleting memory, history, or user-authored files

When asking, provide the smallest safe proposal and the expected benefit.

## Measuring savings

Prefer measured savings over guessed savings.

### Best case: measured before/after

If you can inspect before and after values, compute:

- turn token savings
- turn money savings
- cumulative token savings during this intervention session
- cumulative money savings during this intervention session

Use `scripts/cost_report.py` for the arithmetic when structured numbers are available.

### Fallback: conservative estimate

If exact before and after values are unavailable, give a conservative estimate and label it clearly as estimated. Never present estimated savings as exact.

For conservative estimates:

- estimate only the tokens directly avoided by the intervention
- do not claim output-token savings unless there is evidence
- separate provider-billed amounts from local approximations

## Savings attribution

Read `references/attribution-policy.md` before preparing attribution.

Only attribute savings to causes that are supported by evidence from the current diagnosis. Prefer direct attribution over inferred attribution.

Good attribution examples:

- `history compaction`: context tokens dropped after compaction
- `tool output trimming`: fewer input tokens from replacing raw dumps with summaries or filtered excerpts
- `duplicate-read avoidance`: repeated reads were skipped in the same intervention loop
- `skill/schema overhead avoidance`: unnecessary skill loads or large tool schemas were avoided
- `cache preservation`: cache-write or re-cache costs avoided by acting before ttl expiry
- `model right-sizing`: lower provider rate used for the next step

Attribution rules:

- only claim exact attribution when you have direct before/after or per-action data
- if one action clearly produced most of the savings, say `primary source` and keep the rest as secondary
- if multiple actions overlap, allocate conservatively and mark the split as estimated
- do not force all savings into categories; `unattributed` is allowed
- include only one to three attribution lines in the default user-facing report

Use `scripts/cost_report.py` with `--attribution` when structured action-level evidence is available.

## Currency policy

Decide the reporting currency from the user's language when it is unambiguous:

- chinese -> cny
- japanese -> jpy
- korean -> krw

For ambiguous languages such as english, spanish, french, german, or portuguese, default to usd unless the user or environment already provides a preferred billing currency.

If reliable fx conversion is unavailable, keep usd as the source-of-truth amount and say that the localized figure is unavailable rather than inventing a rate.

## Reporting format

Keep the report short. Use this structure unless the user asked for more detail:

### Cost check
- top waste sources: one to three items
- action taken: what was executed, or `none`
- this turn: saved X tokens, Y currency, or `estimated`
- session total: saved X tokens, Y currency
- savings attribution: one to three short lines, or `none`
- next best step: one short recommendation

If nothing was saved, say so directly and explain why.

## Behavioral rules

- do not optimize blindly; preserve task success first
- do not run multiple diagnostics that repeat the same expensive inspection
- do not paste large raw logs into the answer
- do not overstate savings confidence
- do not change persistent settings without approval
- if the intervention itself would cost more than it is likely to save, say so and keep the advice minimal

## Bundled helpers

- `scripts/cost_report.py`: deterministic token, money, and attribution calculator for before/after comparisons
- `scripts/set_authorization_state.py`: update persistent low-risk automation state when writable
- `references/authorization-state.md`: current persistent permission state
- `references/response-template.md`: concise report template and phrasing guide
- `references/risk-policy.md`: action classification examples
- `references/attribution-policy.md`: conservative attribution rules and category guidance