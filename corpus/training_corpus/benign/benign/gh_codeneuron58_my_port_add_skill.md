---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: CodeNeuron58/My-Portfolio
# corpus-url: https://github.com/CodeNeuron58/My-Portfolio/blob/ef97f99af49ccb39ab88187dc8fde0d9f5e8cccd/ADD_SKILL.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# Adding Skills to the Agent

This guide explains how to find and install new capabilities (skills) for your AI agent using the `skills.sh` platform.

## 1. Browse Skills
Visit [skills.sh](https://skills.sh) to discover available skills. You can search for skills related to:
- Frameworks (React, Vue, etc.)
- Tools (Git, Docker)
- Best Practices (SEO, Accessibility)
- Design (UI/UX, Tailwind)

## 2. Install a Skill
Once you identify a skill you want to add, use the `npx skills add` command in your terminal.

**Command Structure:**
```bash
npx skills add <skill-url>
```

**Example:**
```bash
npx skills add https://skills.sh/skills/ui-ux-pro-max
```
*(Note: Use the actual URL provided on the skills.sh website for the specific skill)*

## 3. Search via CLI
You can also search for skills directly from the command line:

```bash
npx skills search <keyword>
```
Example:
```bash
npx skills search react
```

## 4. What Happens Next?
When you add a skill:
1. The tool downloads the skill configuration to `.agent/skills/<skill-name>`.
2. It generates a `SKILL.md` file containing instructions for the agent.
3. The AI agent (me) will automatically detect this new skill and reference it when performing relevant tasks.

## Troubleshooting
- **Interactive Mode**: If asked to confirm installation, type `y` and press Enter.
- **Multiple Skills**: You can install multiple skills to build a robust toolset for your agent.

## Install Specifically for Me (Antigravity)
To ensure skills are installed only for this agent workspace (in `.agent/`) and reset/remove any unrelated configurations (like `.junie`, `.windsurf`):

Use the `-a` or `--agent` flag:

```bash
npx skills add <skill-name> --agent agent
```
*Note: This targets the generic `.agent` directory format which I use.*

**Example:**
```bash
npx skills add https://skills.sh/skills/ui-ux-pro-max --agent agent
```
This prevents the tool from creating folders for other editors/agents you are not using.