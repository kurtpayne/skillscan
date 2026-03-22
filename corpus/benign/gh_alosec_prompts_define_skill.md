---
name: define skill
version: "1.0"
description: Community skill from alosec/prompts
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: alosec/prompts
# corpus-url: https://github.com/alosec/prompts/blob/HEAD/commands/define-skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# 🎯 Define Skill

Create a new Claude Code skill to automate workflows and guide development patterns.

**Arguments:** `<skill-name>` `[description]`

---

## 📚 What Are Skills?

Skills are auto-activated workflows stored in `.claude/skills/` that:
- Guide Claude through repetitive development patterns
- Reduce context usage with optimized commands
- Ensure consistency across sessions
- Activate automatically based on user intent

---

## 🏗️ Skill Structure

Each skill is a directory with a `SKILL.md` file:

```
.claude/skills/
└── my-skill-name/
    └── SKILL.md
```

---

## 📝 SKILL.md Format

```markdown
---
name: Human Readable Name
description: When to activate this skill. Activate when [trigger conditions].
allowed-tools: Bash, Read, Write, Edit, Glob, Grep
---

# Skill Name

## When to Use
Activate whenever the user asks to:
- [Trigger condition 1]
- [Trigger condition 2]
- [Trigger condition 3]

## Instructions

[Step-by-step workflow with specific commands and best practices]

### Step 1: [Action]
[Details and code examples]

### Step 2: [Action]
[Details and code examples]

## Best Practices

- [Practice 1]
- [Practice 2]

## Integration with Other Skills

This skill works together with:
- **Other Skill Name**: [How they interact]
```

---

## ✨ Skill Creation Workflow

When user provides skill details, follow this process:

1. **Parse Arguments**
   - Extract skill name (kebab-case)
   - Extract description or ask for clarification

2. **Create Directory**
   ```bash
   mkdir -p .claude/skills/[skill-name]
   ```

3. **Generate SKILL.md**
   - Add YAML frontmatter with name, description, allowed-tools
   - Define "When to Use" triggers
   - Write step-by-step instructions
   - Include code examples
   - Add best practices
   - Note integration with other skills

4. **Confirm Creation**
   - Show skill name and location
   - Display activation triggers
   - Explain when Claude will use it

---

## 🎨 Skill Examples

### Simple Skill (Quiet Command)
- **Purpose**: Filter verbose output to reduce context
- **Pattern**: Wrap command with grep filter
- **Tools**: Bash only

### Complex Skill (Feature Development)
- **Purpose**: Guide full feature branch workflow
- **Pattern**: Plan → Branch → Build → Deploy → Iterate
- **Tools**: Multiple (Bash, Read, Write, Edit)

---

## 💡 Best Practices for Skills

1. **Clear Activation Triggers**: Be specific about when skill activates
2. **Step-by-Step Instructions**: Number steps, provide exact commands
3. **Code Examples**: Show concrete command syntax
4. **Context Efficiency**: Use grep patterns, quiet flags, filtered output
5. **Integration Notes**: Explain how skill works with others
6. **Tool Restrictions**: Only list tools the skill actually needs

---

## 🔧 Scope

- **Project Skills**: `.claude/skills/` (this project only)
- **Global Skills**: Not supported (skills are project-specific)

---

## 📖 Additional Resources

- Existing skills in `.claude/skills/` for reference patterns
- Skills activate automatically based on description triggers
- No need to manually invoke skills - Claude recognizes intent
