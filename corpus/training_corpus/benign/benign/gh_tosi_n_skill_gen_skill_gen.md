---
name: skill-gen
description: Generate skills for coding agents by browsing the web with browser-use. Use when the user wants to create a new skill from a URL, blog post, tutorial, GitHub repo, or documentation page. Triggers include "generate a skill", "create skill for X", "skill from this URL", "research and build a skill", "make a skill from this blog", or any request to turn web content into a reusable skill.
allowed-tools: Bash(skill-gen:*), Bash(browser-use:*), Bash(pip:*), Bash(playwright:*)
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: tosi-n/skill-gen
# corpus-url: https://github.com/tosi-n/skill-gen/blob/772e34506c824757583b6945947bd4acee63cf67/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# skill-gen

Generate skills for coding agents by browsing the web with browser-use CLI. You (the coding agent) are the intelligence — browser-use is your browser. No separate LLM API key needed.

## Prerequisites

Before using this skill, browser-use CLI must be installed. Check with:

```bash
skill-gen doctor
```

If `skill-gen` is not found, install everything:

```bash
pip install git+https://github.com/tosi-n/skill-gen.git
playwright install chromium
```

Run `skill-gen doctor` again to confirm all checks pass before proceeding.

## Core Workflow

You generate skills by browsing web pages, reading their content, and writing a SKILL.md. Here is the process:

### Step 1: Open the URL

```bash
browser-use open https://example.com/docs
```

### Step 2: Read the page

```bash
browser-use state                    # See clickable elements with indices
browser-use get text                 # Get full page text
browser-use get text --selector "article"  # Get just the article body
browser-use get text --selector "pre"      # Get code blocks
```

### Step 3: Scroll and explore

```bash
browser-use scroll --amount 500     # Scroll down
browser-use state                   # See new elements
browser-use get text                # Read more content
browser-use screenshot page.png     # Visual context if needed
```

### Step 4: Follow links for more content

```bash
browser-use click 5                 # Click a link by index from state
browser-use get text                # Read the new page
browser-use back                    # Go back
```

### Step 5: Extract what you need

From the page text you read, identify:
- **Tool name** and description
- **Installation commands** (pip install, npm install, brew, etc.)
- **Core commands or API** (CLI usage, function signatures, endpoints)
- **Code examples** (copy them exactly as shown)
- **Configuration** (env vars, config files, flags)
- **Common workflows** (step-by-step patterns)
- **Gotchas** (warnings, limitations, tips)

### Step 6: Write the SKILL.md

Use `skill-gen validate` to check your output:

```bash
skill-gen validate ./skills/my-tool/SKILL.md
```

## Browser-Use CLI Reference

```bash
# Navigation
browser-use open <url>              # Navigate to URL
browser-use back                    # Go back
browser-use close                   # Close browser

# Reading content
browser-use state                   # List clickable elements with indices
browser-use get text                # Full page text
browser-use get text --selector "main"   # Scoped to selector
browser-use get html --selector "pre"    # Get HTML of code blocks
browser-use get title               # Page title
browser-use get attributes 5        # Attributes of element 5

# Interaction
browser-use click <index>           # Click element by index
browser-use type "search query"     # Type into focused element
browser-use input <index> "text"    # Type into specific element
browser-use scroll --amount 500     # Scroll down (negative = up)
browser-use keys Tab                # Press keyboard keys
browser-use select <index> "value"  # Select dropdown option

# Capture
browser-use screenshot page.png     # Screenshot
browser-use screenshot --full page.png   # Full page screenshot

# Tabs
browser-use switch <tab-index>      # Switch tabs
browser-use close-tab               # Close current tab

# Session
browser-use close                   # Close browser session
```

## Multi-Page Research Pattern

When researching a tool across multiple pages:

```bash
# 1. Start at the main page (GitHub repo, docs home)
browser-use open https://github.com/org/tool

# 2. Read the README
browser-use get text

# 3. Find and visit the documentation link
browser-use state    # Find the docs link index
browser-use click 12 # Click it

# 4. Read the docs page
browser-use get text

# 5. Visit API reference
browser-use state
browser-use click 8  # API reference link
browser-use get text

# 6. Visit examples/tutorials
browser-use back
browser-use state
browser-use click 15 # Examples link
browser-use get text

# 7. Close when done
browser-use close
```

For each page, extract relevant information and accumulate it. Then synthesize everything into a single SKILL.md.

## From-URL Shortcut

For quick single-page extraction without manual browsing:

```bash
# Open, extract all text, close — you process the text yourself
browser-use open https://blog.example.com/intro-to-fastapi
browser-use get text > /tmp/page_content.txt
browser-use close
```

Then read the extracted text and write the SKILL.md from it.

For multiple URLs, repeat the pattern for each and combine the findings.

## SKILL.md Structure

Every generated skill must follow this structure:

### Required: YAML Frontmatter

```yaml
---
name: tool-name
description: >
  What the tool does and when to use it. Include trigger phrases
  that help the coding agent activate this skill automatically.
allowed-tools: Bash(tool:*), Bash(related:*)
---
```

### Required Fields

- `name` — kebab-case identifier
- `description` — what it does + trigger phrases for when to use it
- `allowed-tools` — Bash tool patterns the skill needs

### Structure Rules

- Body under 500 lines and 5000 words
- Sections: Prerequisites, Core Workflow, Commands, Common Patterns, Configuration, Gotchas
- Code examples with language annotations on fenced blocks
- Progressive disclosure: overview first, details later
- No `references/` directory

### Minimal Example

```markdown
---
name: httpie
description: HTTP client for the command line. Use when making API requests, testing endpoints, or sending HTTP calls.
allowed-tools: Bash(http:*), Bash(https:*)
---

# httpie

Modern HTTP client.

## Installation

\`\`\`bash
pip install httpie
\`\`\`

## Core Usage

\`\`\`bash
http GET https://api.example.com/items
http POST https://api.example.com/items name="widget" price:=9.99
http -a user:pass GET https://api.example.com/secure
\`\`\`

## Common Patterns

- `:=` for non-string JSON values
- `==` for query parameters
- Pipe JSON: `echo '{"key":"val"}' | http POST example.com`
```

## Scaffolding and Validation

```bash
# Create a blank skill scaffold from a template
skill-gen init --name "my-tool" --template basic --output ./skills/my-tool/
skill-gen init --name "my-api" --template api --output ./skills/my-api/
skill-gen init --name "my-cli" --template cli --output ./skills/my-cli/

# Validate a skill you wrote
skill-gen validate ./skills/my-tool/SKILL.md
```

Templates: `basic`, `browser`, `api`, `cli`, `composite`.

## Handling Different Content Types

### Blog Posts / Tutorials

Focus on extracting: the core concept, step-by-step instructions, and code examples. Blog content is often narrative — distill it into concise procedural skill instructions.

### GitHub READMEs

Focus on: installation, quick start examples, API/CLI reference, and configuration. READMEs are already structured — map their sections to skill sections.

### API Documentation

Focus on: authentication setup, endpoint patterns, request/response examples, error codes, and rate limits. Use the `api` template.

### CLI Tool Docs

Focus on: installation, command reference with flags, pipeline patterns, and shell integration. Use the `cli` template.

## Tips

- Always run `browser-use state` before clicking — indices change between pages
- Use `browser-use get text --selector "article"` or `--selector "main"` to skip nav/footer noise
- For JavaScript-heavy sites, wait a moment after `open` before reading: `browser-use scroll --amount 0`
- Use `browser-use screenshot` when page layout matters (tables, diagrams)
- Close the browser when done: `browser-use close`
- Keep generated skills under 500 lines — be concise, focus on what matters
- Always validate: `skill-gen validate ./path/to/SKILL.md`