---
name: design
version: "1.0"
description: Generates design document with Simple Made Easy evaluation
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: sato-dev1234/claude-code-sample
# corpus-url: https://github.com/sato-dev1234/claude-code-sample/blob/HEAD/skills/design/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# /design

Generates design document with Simple Made Easy evaluation.

## Progress Checklist

```
- [ ] Step 1: Resolve ticket
- [ ] Step 2: Read ticket contents
- [ ] Step 3: Load project knowledge
- [ ] Step 4: Launch Plan agent
- [ ] Step 5: Save design.md
- [ ] Step 6: Create implementation tasks
- [ ] Step 7: Report summary in Japanese
```

## Steps

1. Resolve ticket:
   - If TICKET_ID provided in args → use it
   - Else → invoke ticket-reader list, ask user to select via AskUserQuestion

2. Read ticket contents → `TICKET_INFO`

3. Load project knowledge:
   - Invoke knowledge-reader agent: `OPERATION=resolve TICKET_PATH=$TICKET_PATH WORKFLOW=/design`
   - If KNOWLEDGE_ERROR=true → KNOWLEDGE = []
   - If KNOWLEDGE_STATUS=empty → KNOWLEDGE = []
   - Otherwise → KNOWLEDGE = parsed knowledge array

4. Launch Plan agent (via Task tool with subagent_type=Plan) to create design document with TICKET_INFO, KNOWLEDGE, CONFIG, and Simple Made Easy evaluation.

5. Save design.md:
   - If exists: Ask user for overwrite confirmation, create backup if yes
   - Write <TICKET_PATH>/design.md

6. Create implementation tasks from design:

   ### 6.1 Parse file structure
   - Parse design.md for file structure sections
   - Extract all implementation files (exclude test files)
   - For each file, note: path, responsibility, dependencies

   ### 6.2 Infer dependencies
   - Read existing source files to understand import/require relationships
   - Build dependency graph from design's file structure section
   - Detect circular dependencies → report error if found

   ### 6.3 Create implementation tasks
   - Get current /design task ID from TaskList (if running in task context)
   - For each implementation file in design:
     - TaskCreate with:
       - subject: `Implement: <filename>` (unified format, no Test: prefix)
       - description: `Path: <filepath>\nResponsibility: <responsibility>\nDependencies: <list of dependent files>`
       - activeForm: "Implementing <filename>"
       - metadata: {autoRun: false}
     - Store created task ID for dependency linking
   - Skip test file tasks (test files are created during TDD cycle)

   ### 6.4 Set blockedBy relationships for implementation tasks
   - For each created task:
     - Find tasks for files this file depends on
     - TaskUpdate(addBlockedBy: [dependent task IDs])
   - If /design task exists: all implementation tasks are blockedBy design task

   ### 6.5 Create workflow tasks (blockedBy: all Implement tasks)
   - Collect all Implement task IDs → IMPLEMENT_TASK_IDS
   - TaskCreate: /refine-loop type=ac (required, auto-run after TDD)
     - subject: "Run AC review"
     - description: "Run acceptance criteria review after TDD completion"
     - activeForm: "Running AC review"
     - metadata: {skill: "refine-loop", args: "type=ac ticket=$TICKET_ID scope=uncommitted", autoRun: true}
     - blockedBy: IMPLEMENT_TASK_IDS (all implementation tasks)
   - TaskCreate: /write-documents (optional, independent)
     - subject: "Run /write-documents"
     - description: "Generate documentation"
     - activeForm: "Running /write-documents"
     - metadata: {skill: "write-documents", args: "ticket=$TICKET_ID"}
     - blockedBy: [] (independent)
   - TaskCreate: /ui-test-design (optional, independent)
     - subject: "Run /ui-test-design"
     - description: "Generate UI test scenarios"
     - activeForm: "Running /ui-test-design"
     - metadata: {skill: "ui-test-design", args: "ticket=$TICKET_ID"}
     - blockedBy: [] (independent)
   - Do not create /create-pr task (requires human review, manual execution)

7. Report summary in Japanese:
   - Design document location
   - Number of implementation tasks created
   - Workflow tasks created (/refine-loop type=ac, /write-documents, /ui-test-design)
   - Task dependencies (show dependency graph)
   - Any circular dependency warnings
   - Remind user: Run /tdd to start implementation, /create-pr requires manual execution after review