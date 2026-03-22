---
name: create skill
version: "1.0"
description: Generate a new Claude Skill with proper structure and YAML frontmatter using official documentation as reference
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: alexanderop/claude-code-builder
# corpus-url: https://github.com/alexanderop/claude-code-builder/blob/HEAD/commands/create-skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# /create-skill

## Purpose
Generate a new Claude Skill with proper structure and YAML frontmatter using official documentation as reference

## Contract
**Inputs:**
- `$1` — SKILL_NAME (lowercase, kebab-case, max 64 characters)
- `$2` — DESCRIPTION (what the skill does and when to use it, max 1024 characters)
- `--personal` — create in ~/.claude/skills/ (default)
- `--project` — create in .claude/skills/

**Outputs:** `STATUS=<CREATED|EXISTS|FAIL> PATH=<path>`

## Instructions

1. **Validate inputs:**
   - Skill name: lowercase letters, numbers, hyphens only (max 64 chars)
   - Description: non-empty, max 1024 characters, no angle brackets (< or >)
   - Description should include both WHAT the skill does and WHEN to use it
   - If user provides additional frontmatter properties, validate against allowed list:
     - **Allowed:** name, description, license, allowed-tools, metadata
     - **Warning** (not error) for unexpected properties like version, author, tags
     - Inform user that unexpected properties may cause issues during packaging

2. **Determine target directory:**
   - Personal (default): `~/.claude/skills/{{SKILL_NAME}}/`
   - Project: `.claude/skills/{{SKILL_NAME}}/`

3. **Check if skill already exists:**
   - If exists: output `STATUS=EXISTS PATH=<path>` and stop

4. **Analyze what bundled resources this skill needs:**

   Based on the skill name and description, intelligently determine which bundled resources would be valuable:

   **Create scripts/ directory when:**
   - Skill involves file manipulation (PDF, images, documents, etc.)
   - Skill requires deterministic operations (data processing, conversions)
   - Same code would be rewritten repeatedly
   - Examples: pdf-editor, image-processor, data-analyzer, file-converter

   **Create references/ directory when:**
   - Skill needs reference documentation (API docs, schemas, specifications)
   - Detailed information would make SKILL.md too long (>5k words)
   - Domain knowledge needs to be documented (company policies, standards)
   - Examples: api-client, database-query, brand-guidelines, coding-standards

   **Create assets/ directory when:**
   - Skill uses templates or boilerplate code
   - Skill needs brand assets (logos, fonts, images)
   - Skill creates documents from templates (presentations, reports)
   - Examples: frontend-builder, brand-guidelines, document-generator, presentation-maker

   **Questions to ask user for clarification (only if unclear):**
   - "Will this skill need to run any scripts repeatedly?" (→ scripts/)
   - "Does this skill need reference documentation like API docs or schemas?" (→ references/)
   - "Will this skill use templates or assets like logos/fonts/boilerplate?" (→ assets/)

   **Communicate the decision:**
   After analysis, inform the user which directories will be created and why:
   - Example: "Based on the description, I'll create scripts/ for PDF manipulation utilities and references/ for schema documentation."
   - Be transparent about the reasoning
   - It's better to include a directory with placeholders than to omit one that might be needed

5. **Create skill directory structure based on analysis:**

   Always create:
   ```
   {{SKILL_NAME}}/
   └── SKILL.md (required)
   ```

   Conditionally create based on Step 4 analysis:
   ```
   ├── scripts/ (if determined needed)
   │   └── example.py (executable placeholder with TODO)
   ├── references/ (if determined needed)
   │   └── README.md (documentation placeholder with guidance)
   └── assets/ (if determined needed)
       └── README.md (asset placeholder with examples)
   ```

6. **Generate SKILL.md using this template:**
   ```markdown
   ---
   name: {{SKILL_NAME}}
   description: {{DESCRIPTION}}
   # Optional fields (uncomment if needed):
   # allowed-tools: ["Read", "Write", "Bash"]  # Restrict to specific tools
   # metadata:
   #   category: "development"
   #   version: "1.0.0"  # For tracking in your project
   # license: "MIT"  # For shared skills
   ---

   # {{Title Case Skill Name}}

   ## Overview

   [TODO: 1-2 sentences explaining what this skill does and why it's valuable]

   ## When to Use

   [TODO: Specific triggers and scenarios where this skill should be invoked]

   ## Structuring This Skill

   Choose an organizational pattern:

   **Workflow-Based** (sequential) - TDD workflows, git commits, deployments
   - Structure: Overview → Step 1 → Step 2 → Step 3...

   **Task-Based** (operations) - File tools, API operations, data transforms
   - Structure: Overview → Quick Start → Operation A → Operation B...

   **Reference-Based** (guidelines) - Brand standards, coding rules, checklists
   - Structure: Overview → Guidelines → Specifications → Examples

   **Capabilities-Based** (integrated) - Product management, debugging, systems
   - Structure: Overview → Core Capabilities → Feature 1 → Feature 2...

   Patterns can be mixed. Delete this section after choosing.

   [TODO: Delete this "Structuring This Skill" section after choosing your approach]

   ## Instructions

   [TODO: Provide clear, step-by-step guidance using imperative/infinitive language]

   [TODO: Reference any bundled resources (scripts, references, assets) so Claude knows how to use them]

   Example structure:
   1. First major step
   2. Second major step
   3. Third major step

   ## Bundled Resources

   [TODO: Document bundled resources. Delete unused subsections.]

   **scripts/** - Executable code run directly (not loaded into context)
   - Example: `scripts/process_data.py` - Processes CSV and generates reports

   **references/** - Documentation loaded into context when needed
   - Example: `references/api_docs.md` - API endpoint documentation

   **assets/** - Files used in output (not loaded into context)
   - Example: `assets/template.pptx` - Presentation template

   ## Examples

   [TODO: Show concrete examples with realistic user requests]

   ```
   User: "Help me [specific task]"
   Claude: [How the skill responds]
   ```

   ## Progressive Disclosure

   Keep SKILL.md <5k words. Move detailed info to references/. Three-level loading:
   1. Metadata (~100 words) - Always in context
   2. SKILL.md - Loaded when triggered
   3. Bundled resources - Loaded as needed
   ```

7. **Create bundled resource placeholders (based on Step 4 analysis):**

   For each directory determined in Step 4, create appropriate placeholder files:

   **scripts/** → Create `scripts/example.py` (executable Python template with TODO comment)
   **references/** → Create `references/README.md` (documentation template explaining purpose)
   **assets/** → Create `assets/README.md` (asset placeholder explaining common types)

   Make scripts executable: `chmod +x scripts/*.py`

8. **Follow official guidelines:**
   - Name: lowercase, numbers, hyphens only (max 64 chars)
   - Description: Include triggers and use cases (max 1024 chars)
   - Instructions: Clear, step-by-step guidance
   - Keep skills focused on single capabilities
   - Make descriptions specific with trigger keywords

9. **Output:**
   - Print: `STATUS=CREATED PATH={{full_path}}`
   - Summarize what was created and why (list directories + reasoning)
   - Remind user to populate placeholders and complete [TODO] items

## Constraints
- Skills are model-invoked (Claude decides when to use them)
- Description must be specific enough for Claude to discover when to use it
- One skill = one capability (stay focused)
- Use forward slashes in all file paths
- Valid YAML syntax required in frontmatter

## Frontmatter Properties

**Required:**
- `name` - Lowercase hyphen-case identifier (max 64 chars, matches directory name)
- `description` - What it does + when to use it (max 1024 chars, no angle brackets)

**Optional:**
- `allowed-tools: ["Read", "Write", "Bash"]` - Restrict Claude to specific tools
- `metadata: {category: "dev", version: "1.0"}` - Custom tracking fields
- `license: "MIT"` - License for shared skills

**Prohibited** (causes warnings):
- `version`, `author`, `tags` - Use metadata or description instead

## Examples

**Simple workflow skill:**
```bash
/create-skill commit-helper "Generate clear git commit messages from diffs. Use when writing commits or reviewing staged changes."
```
*Claude will determine: No bundled resources needed - just workflow guidance*

**File manipulation skill:**
```bash
/create-skill pdf-processor "Extract text and tables from PDF files. Use when working with PDFs, forms, or document extraction."
```
*Claude will determine: Needs scripts/ directory for PDF manipulation utilities*

**API integration skill:**
```bash
/create-skill api-client "Make REST API calls and handle responses. Use for API testing and integration work with the company API."
```
*Claude will determine: Needs references/ directory for API documentation and schemas*

**Image processing skill:**
```bash
/create-skill image-processor "Resize, rotate, and convert images. Use when editing images or batch processing files."
```
*Claude will determine: Needs scripts/ directory for image manipulation operations*

**Brand guidelines skill:**
```bash
/create-skill brand-guidelines "Apply company brand guidelines to designs. Use when creating presentations, documents, or marketing materials."
```
*Claude will determine: Needs references/ for guidelines + assets/ for logos, fonts, templates*

**Frontend builder skill:**
```bash
/create-skill frontend-builder "Build responsive web applications with React. Use when creating new frontend projects or components." --project
```
*Claude will determine: Needs scripts/ for build tools + assets/ for boilerplate templates*

**Database query skill:**
```bash
/create-skill database-query "Query and analyze database tables. Use when working with SQL, BigQuery, or data analysis tasks." --project
```
*Claude will determine: Needs references/ for schema documentation*

**How Claude determines what's needed:**
- Mentions "PDF", "images", "documents", "convert" → scripts/
- Mentions "API", "database", "guidelines", "standards" → references/
- Mentions "templates", "boilerplate", "brand", "presentations" → assets/
- Simple workflow/process skills → SKILL.md only

**Adding optional frontmatter properties:**

After creating a skill, you can manually edit SKILL.md to add optional frontmatter properties:

```markdown
---
name: database-query
description: Query and analyze database tables. Use when working with SQL, BigQuery, or data analysis tasks.
allowed-tools: ["Bash", "Read", "Grep"]
metadata:
  category: "data"
  version: "1.0.0"
  team: "analytics"
license: "MIT"
---
```

## Post-Creation Workflow

**1. Edit** - Complete [TODO] placeholders, populate bundled resources, add concrete examples

**2. Test** - Restart Claude Code, test with trigger queries matching description

**3. Validate** - Check frontmatter properties, description clarity, no sensitive data

**4. Iterate** - Use on real tasks, update based on struggles/feedback

**Optional:**
- Package for distribution: Use packaging tools or `/create-plugin`
- Share with team: Distribute .zip or via plugin marketplace

## Example: Well-Structured Skill

Here's an example of a production-quality skill to demonstrate best practices:

**artifacts-builder** - A skill for creating complex React/TypeScript artifacts with shadcn/ui

```
artifacts-builder/
├── SKILL.md (focused, ~75 lines)
└── scripts/
    ├── init-artifact.sh (323 lines - initializes React+Vite+shadcn project)
    ├── bundle-artifact.sh (54 lines - bundles to single HTML)
    └── shadcn-components.tar.gz (pre-packaged shadcn/ui components)
```

**SKILL.md structure:**

```markdown
---
name: artifacts-builder
description: Suite of tools for creating elaborate, multi-component claude.ai HTML artifacts using modern frontend web technologies (React, Tailwind CSS, shadcn/ui). Use for complex artifacts requiring state management, routing, or shadcn/ui components - not for simple single-file HTML/JSX artifacts.
license: Complete terms in LICENSE.txt
---

# Artifacts Builder

To build powerful frontend claude.ai artifacts, follow these steps:
1. Initialize the frontend repo using `scripts/init-artifact.sh`
2. Develop your artifact by editing the generated code
3. Bundle all code into a single HTML file using `scripts/bundle-artifact.sh`
4. Display artifact to user
5. (Optional) Test the artifact

**Stack**: React 18 + TypeScript + Vite + Parcel (bundling) + Tailwind CSS + shadcn/ui

## Design & Style Guidelines

VERY IMPORTANT: To avoid what is often referred to as "AI slop", avoid using excessive centered layouts, purple gradients, uniform rounded corners, and Inter font.

## Quick Start

### Step 1: Initialize Project
Run the initialization script to create a new React project:
```bash
bash scripts/init-artifact.sh <project-name>
cd <project-name>
```

This creates a fully configured project with:
- ✅ React + TypeScript (via Vite)
- ✅ Tailwind CSS 3.4.1 with shadcn/ui theming system
- ✅ Path aliases (`@/`) configured
- ✅ 40+ shadcn/ui components pre-installed
- ✅ All Radix UI dependencies included
- ✅ Parcel configured for bundling
- ✅ Node 18+ compatibility

### Step 2: Develop Your Artifact
To build the artifact, edit the generated files. See **Common Development Tasks** below for guidance.

### Step 3: Bundle to Single HTML File
To bundle the React app into a single HTML artifact:
```bash
bash scripts/bundle-artifact.sh
```

This creates `bundle.html` - a self-contained artifact with all JavaScript, CSS, and dependencies inlined.

### Step 4: Share Artifact with User
Finally, share the bundled HTML file in conversation with the user so they can view it as an artifact.

### Step 5: Testing/Visualizing the Artifact (Optional)
Note: This is a completely optional step. Only perform if necessary or requested.

## Reference
- **shadcn/ui components**: https://ui.shadcn.com/docs/components
```

**What makes this skill excellent:**

1. **Clear, specific description** - States exactly what it does (React artifacts with shadcn/ui) and when NOT to use it (simple HTML)

2. **Task-Based organizational pattern** - Uses numbered steps (Quick Start → Step 1, 2, 3...) for clear workflow

3. **Practical scripts/** - Contains executable utilities that prevent rewriting the same setup code:
   - `init-artifact.sh` - Automates 20+ setup steps (Vite, Tailwind, shadcn/ui, dependencies)
   - `bundle-artifact.sh` - Bundles multi-file React app into single HTML
   - `shadcn-components.tar.gz` - Pre-packaged components (saves installation time)

4. **Focused SKILL.md** - Only ~75 lines, moves implementation details to scripts

5. **Domain-specific guidance** - Includes "Design & Style Guidelines" section with specific advice

6. **Optional license field** - Uses `license: Complete terms in LICENSE.txt` since Apache 2.0 is verbose

7. **Progressive disclosure** - Metadata (~50 words), SKILL.md core workflow (<2k words), scripts executed without loading

8. **Explicit references** - Points to external docs (shadcn/ui) rather than duplicating them

**Claude Code would create scripts/ automatically for this skill because:**
- Description mentions "tools", "React", "Tailwind CSS", "shadcn/ui" (technical setup)
- Name "builder" implies construction/automation
- Description emphasizes "elaborate, multi-component" (complexity requiring tooling)

## Reference
Based on official Claude Code Agent Skills documentation:
- Personal skills: `~/.claude/skills/`
- Project skills: `.claude/skills/`
- Changes take effect on next Claude Code restart
- Test by asking questions matching the description triggers