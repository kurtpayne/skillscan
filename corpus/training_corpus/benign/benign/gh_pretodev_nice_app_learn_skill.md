---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: pretodev/nice_app
# corpus-url: https://github.com/pretodev/nice_app/blob/bb803badef90a157d489ec0a14a3a1c0f569a865/learn-skill.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
## 1) Start with a **single, testable outcome**

A “skill agent” should be describable in one sentence:

* “Given a repo, produce an onboarding doc.”
* “Given a ticket, generate a PR plan + checklists.”
* “Given a log file, identify root cause + next steps.”

If it has *multiple* outcomes, split it into multiple skills.

## 2) Define the **contract** (inputs → outputs)

Write this like an API:

**Inputs**

* Required fields (e.g., `repo_path`, `ticket_url`, `constraints`)
* Optional fields (e.g., `tone`, `max_depth`, `audience`)

**Outputs**

* One primary artifact (markdown/doc/json)
* Optional attachments (diff, checklist, citations, risk list)

**Quality bar**

* “Must cite sources when using web.”
* “Must include reproduction steps.”
* “Must list assumptions.”

This contract is what prevents agents from “being creative” in the wrong places.

## 3) Give it a tight **role + boundaries**

Good skill agents are boring and consistent.

* What it **does**
* What it **doesn’t** do
* When it must **ask** (or fail gracefully) vs assume

Example boundary rules:

* “Never modify production configs.”
* “Never run destructive commands without an explicit flag.”
* “If inputs are missing, infer defaults only if low risk.”

## 4) Tooling: prefer **few tools**, strong patterns

A skill agent should have:

* the minimum tools needed
* a deterministic “tool use loop”

Common loops:

* **Gather → Analyze → Produce → Verify**
* **Plan → Execute steps → Summarize results**

Make the agent *always* produce:

* “What I did”
* “What I found”
* “What I’m not sure about”
* “Next actions”

## 5) Build a **guardrail checklist** (every run)

This is the secret sauce. A checklist prevents regressions.

Examples:

* ✅ Confirm goal + constraints match contract
* ✅ Identify missing inputs
* ✅ List assumptions
* ✅ Run “sanity checks” on output (format, completeness)
* ✅ Include edge cases + failure modes
* ✅ If using web: include citations
* ✅ If writing code: include tests / minimal validation

## 6) Use **structured output** by default

Even if the final artifact is prose, generate an internal structure.

Patterns that work well:

* JSON / YAML “result schema”
* Markdown template with strict headings
* Tables for decisions / tradeoffs / risks

This makes evaluation and iteration much easier.

## 7) Add **self-verification**

Before returning, the agent should ask:

* “Did I satisfy the contract?”
* “Did I include required sections?”
* “Did I contradict myself?”
* “Are there unsafe / destructive steps?”

A simple “verify pass” improves reliability a lot.

## 8) Create **golden examples + adversarial tests**

Don’t just test happy paths.

Make a tiny suite:

* 3 “normal” inputs
* 2 “messy” inputs (missing fields, ambiguous)
* 2 “hostile” inputs (prompt injection, tool misuse attempts)

Evaluate:

* correctness
* completeness
* consistency of formatting
* tool usage (did it overuse tools?)
* safety (did it refuse bad requests?)

## 9) Observability: log *why* it did things

If you can, store:

* which tools it used
* intermediate decisions
* confidence/uncertainty notes
* what it refused

This makes debugging *way* faster than tweaking prompts blindly.

## 10) Common failure patterns (and fixes)

* **Too broad scope** → split into multiple skills
* **Prompt injection via inputs** → treat inputs as data, never instructions; sanitize; allowlist tool actions
* **Tool spam** → cap tool calls; require plan before actions
* **Inconsistent outputs** → enforce templates/schemas
* **Hallucinated facts** → require citations or “unknown” explicitly

---

### A solid default template you can copy for any Skill Agent

**System / instructions skeleton (conceptual):**

* Role: “You are `X` skill agent.”
* Contract: inputs/outputs
* Constraints: what not to do
* Process: Gather → Analyze → Produce → Verify
* Output format: strict sections
* Tool rules: when to use each tool + limits
* Safety rules: refuse unsafe/destructive actions