---
name: mature
version: "1.0"
description: Transition from vibe to mature phase — structured maturation sequence
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: mathonsunday/phase-workflow
# corpus-url: https://github.com/mathonsunday/phase-workflow/blob/HEAD/templates/mature-SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Transition to Mature Phase

Run the full maturation sequence. Each step requires explicit user approval before moving to the next.

**CRITICAL**: Do NOT advance to the next step until the user explicitly says the current step is done. Present your work, ask for feedback, and wait. The user may have questions, want changes, or need to discuss what they're seeing. Moving on without sign-off is not acceptable.

## Steps

### 1. Switch phase

Write `mature` to `.claude/phase`.

**Wait for user sign-off before proceeding.**

### 2. Check dependencies

Verify these dev dependencies are installed. If any are missing, install them:

- `husky`
- `lint-staged`
- `@commitlint/cli`
- `@commitlint/config-conventional`
- `prettier`
- `knip`
- `eslint-plugin-redos`
- `@mathonsunday/mutation-test-gen`

Run `npm install` if anything was added. Present what was found/installed.

**Wait for user sign-off before proceeding.**

### 3. Generate architecture diagram

Create a mermaid diagram of the current architecture by reading through `src/` and `api/`. Present it to the user for review. Ask if anything should be simplified or removed before proceeding. The user may ask questions about the architecture, request changes to the diagram, or identify cleanup work. Do all of that before moving on.

**Wait for user sign-off before proceeding.**

### 4. Dead code audit

Run `npx knip` and present the results. Ask the user which unused exports, files, or dependencies should be removed. Remove what they approve.

**Wait for user sign-off before proceeding.**

### 5. Mutation-guided test generation

**You MUST use the `@mutation-test-gen/` framework for all test generation. Do NOT write tests manually — hand-written tests without mutation guidance are low quality and miss real bug patterns.**

Run `npx mutation-test-gen` against all source files in `src/` and `api/` to generate mutations, then use those mutations to write targeted tests:

```bash
npx mutation-test-gen src/**/*.ts src/**/*.tsx api/**/*.ts
```

Do NOT use a curated "core modules" list. Every source file gets mutations generated. Present the mutations and use them to guide writing tests that catch real bugs. Focus on boundary conditions and error paths. Every test should be traceable to a specific mutation.

**Wait for user sign-off before proceeding.**

### 6. Fix lint errors

Now that tests exist to catch regressions, fix any lint errors surfaced by the stricter mature-phase config. Run `npm run lint` and address issues. Re-run tests after each batch of fixes to confirm nothing broke.

**Important**: This step MUST come after test generation. Lint fixes (especially complexity refactors) restructure code and can introduce subtle bugs. Tests written against the pre-refactored code act as a safety net.

**Wait for user sign-off before proceeding.**

### 7. Confirm activation

Tell the user:

- Strict pre-commit hooks are now active
- Dead code detection blocks commits
- Security scanning blocks commits
- Tests must pass to commit
- Commit messages must follow conventional commits format
- Run `/vibe` to switch back if needed