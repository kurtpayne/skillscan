---
name: create skill
version: "1.0"
description: Create custom Claude skills with guided workflow
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: Alon2904/claude-code-skill-creator
# corpus-url: https://github.com/Alon2904/claude-code-skill-creator/blob/HEAD/commands/create-skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Create Skill Command

Automates the creation of custom Claude skills with guided workflows.

## Workflow

Follow these steps to create a custom skill:

### Step 1: Gather Requirements

Ask the user what skill they want to create:
- "What should this skill help you accomplish?"
- "What types of tasks or files will this skill handle?"
- "Will you need any scripts, reference documentation, or template assets?"

Get a clear understanding of:
- **Purpose**: What should the skill do?
- **Use cases**: When should Claude use this skill?
- **Required capabilities**: Scripts, references, or assets needed?

### Step 2: Determine Location

Check the current working directory and ask user where to create the skill.

Present two options:

**Option 1: Current Project (.claude/skills/)**
- Best for project-specific skills
- Claude will have full context of the user's codebase
- Skill will be tailored to their specific project

**Option 2: For Sharing (skills/custom/ or custom path)**
- Best for general-purpose skills to share
- Creates a packaged .zip file
- Can be distributed to others

Ask: "Where would you like to create this skill?"

Store the chosen path as `$SKILL_BASE_PATH`.

### Step 3: Generate Skill Name

If the user hasn't provided a skill name, generate one following these rules:
- Use hyphen-case (e.g., "api-test-helper", "json-validator")
- Lowercase letters, digits, and hyphens only
- Max 40 characters
- Descriptive and clear
- No starting/ending hyphens or consecutive hyphens

Confirm the generated name with the user.

### Step 4: Locate Helper Scripts

The helper scripts are located at:
```
skills/skill-creator/scripts/init_skill.py
skills/skill-creator/scripts/package_skill.py
skills/skill-creator/scripts/quick_validate.py
```

These come from Anthropic's official skills repository (included as a git submodule).

### Step 5: Initialize Skill Scaffold

Run the init script to create the basic structure:

```bash
python skills/skill-creator/scripts/init_skill.py <skill-name> --path $SKILL_BASE_PATH
```

This creates:
- `$SKILL_BASE_PATH/<skill-name>/` directory
- `SKILL.md` with template
- `scripts/example.py` (example script)
- `references/api_reference.md` (example reference)
- `assets/example_asset.txt` (example asset)

### Step 6: Customize SKILL.md

Read the generated SKILL.md file and customize it based on user requirements:

**Update frontmatter:**
- Keep the `name` field as-is (matches directory name)
- Replace the description with a clear, specific description
- Add optional fields if needed (license, allowed-tools, metadata)

**Update Overview section:**
- Replace TODO with 1-2 sentences explaining what the skill enables

**Choose structure pattern:**
- Workflow-Based: For sequential processes
- Task-Based: For tool collections
- Reference/Guidelines: For standards or specifications
- Capabilities-Based: For integrated systems

Delete the "Structuring This Skill" guidance section after choosing.

**Add main content:**
- Replace TODO sections with actual instructions and examples
- Include code samples, decision trees, or workflows as appropriate
- Reference any scripts, assets, or references being included

**Update Resources section:**
- Keep explanations for directories that are being used
- Remove explanations for directories that aren't needed

### Step 7: Customize Supporting Files

Based on user requirements:

**For scripts/ directory:**
- If custom scripts are needed, replace `example.py` with actual implementation
- If no scripts needed, delete the scripts/ directory entirely
- Make scripts executable: `chmod +x scripts/*.py`

**For references/ directory:**
- If reference documentation is needed, replace `api_reference.md` with actual content
- If no references needed, delete the references/ directory entirely

**For assets/ directory:**
- If template files/assets are needed, add them and delete `example_asset.txt`
- If no assets needed, delete the assets/ directory entirely

### Step 8: Ask Clarifying Questions

During customization, ask the user for clarification on:
- Specific implementation details for scripts
- Content for reference documentation
- Whether certain features should be included
- Examples they'd like to see in the documentation

Use the AskUserQuestion tool when needed.

### Step 9: Clean Up

Remove all TODO markers and template placeholder text from files.

### Step 10: Validate and Package

Run the package script which automatically validates before packaging:

```bash
python skills/skill-creator/scripts/package_skill.py $SKILL_BASE_PATH/<skill-name>
```

This will:
- Validate the skill structure
- Check frontmatter format
- Create a distributable .zip file in the current directory

If validation fails, fix the issues and retry.

### Step 11: Show Summary

Display a summary of what was created:

```
✅ Skill created successfully!

📁 Location: $SKILL_BASE_PATH/<skill-name>/
📦 Package: <skill-name>.zip
```

**If created in current project (.claude/skills/):**
```
Files created:
- SKILL.md
- [List any scripts, references, or assets]

Next steps:
1. Test the skill by asking Claude to use it
2. Example: "Use the <skill-name> skill to [task]"
3. Edit .claude/skills/<skill-name>/SKILL.md to refine as needed

💡 Tip: This skill was created in your project, so Claude has full
context of your codebase. The skill can reference your specific
APIs, patterns, and conventions.
```

**If created for sharing:**
```
Files created:
- SKILL.md
- [List any scripts, references, or assets]
- <skill-name>.zip (packaged for distribution)

Next steps:
1. Test the skill locally
2. Share <skill-name>.zip with your team
3. Upload to Claude.ai or distribute via GitHub

💡 Tip: To share this skill, others can:
- Upload the .zip to Claude.ai
- Extract and copy to their .claude/skills/ directory
```

## Important Notes

- Always use existing scripts from skills/skill-creator/scripts/
- Follow the skill structure patterns from Anthropic's skills
- Keep SKILL.md concise (<5k words); move detailed content to references/
- Use imperative/infinitive form in instructions, not second person
- Ensure all paths are relative
- Scripts should be executable and include --help information
- Validate before packaging to catch errors early

## Error Handling

If any step fails:
1. Display the error message clearly
2. Suggest fixes based on the error
3. Ask if the user wants to retry or make changes
4. Don't proceed to next steps until current step succeeds