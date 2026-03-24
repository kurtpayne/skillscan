---
name: slite
version: "1.0"
description: Interact with Slite knowledge base - search, read, create, and manage notes. Use when user wants to work with Slite d...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: Sytex/agent-skills
# corpus-url: https://github.com/Sytex/agent-skills/blob/HEAD/skills/slite/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Slite Integration

Search, read, create, update, and manage notes in Slite.

## Commands

All commands use the script: `~/.claude/skills/slite/slite`

### Read Operations

| Command | Description |
|---------|-------------|
| `me` | Get current user info |
| `search <query> [flags]` | Search notes with optional filters |
| `ask <question> [--parent <id>]` | Ask AI a question (optionally scoped) |
| `list [parentId]` | List notes (optionally under a parent) |
| `get <noteId> [md\|html]` | Get note content |
| `children <noteId>` | Get direct child notes |
| `tree <noteId> [depth]` | Show note hierarchy tree (default depth: 3) |
| `search-users <query>` | Search users by name/email |

### Search Flags

| Flag | Description |
|------|-------------|
| `--parent <id>` | Filter results within a parent note |
| `--depth <n>` | Search depth (1-3) |
| `--include-archived` | Include archived notes in results |
| `--after <date>` | Notes edited after date (ISO format) |
| `--page <n>` | Page number for pagination |
| `--limit <n>` | Results per page |

### Write Operations

| Command | Description |
|---------|-------------|
| `create <title> [markdown] [parentId]` | Create a new note |
| `append <noteId> <markdown>` | **SAFE**: Add content to END of note |
| `prepend <noteId> <markdown>` | **SAFE**: Add content to START of note |
| `update <noteId> [title] [markdown]` | **DANGER**: REPLACES entire note content! |
| `delete <noteId>` | Delete note (irreversible!) |
| `archive <noteId> [true\|false]` | Archive or unarchive |
| `verify <noteId> [until]` | Mark as verified |
| `outdated <noteId> <reason>` | Flag as outdated |

> **WARNING**: The `update` command REPLACES all existing content. Use `append` or `prepend` to add content without losing existing content.

## Usage Examples

### Search for notes
```bash
~/.claude/skills/slite/slite search "onboarding"
```

### Search within a specific section
```bash
~/.claude/skills/slite/slite search "deploy" --parent abc123 --depth 2
```

### Explore note hierarchy
```bash
~/.claude/skills/slite/slite tree abc123
```

### Ask a question scoped to a section
```bash
~/.claude/skills/slite/slite ask "How do we handle deployments?" --parent abc123
```

### Get a specific note in markdown
```bash
~/.claude/skills/slite/slite get abc123 md
```

### Create a new note
```bash
~/.claude/skills/slite/slite create "Meeting Notes" "## Attendees\n- Alice\n- Bob"
```

### Add content to a note (SAFE - preserves existing content)
```bash
# Add to end of note
~/.claude/skills/slite/slite append abc123 "## New Section\n\nContent here"

# Add to beginning of note
~/.claude/skills/slite/slite prepend abc123 "## Important Notice\n\nRead this first!"
```

### Replace entire note (DANGEROUS - loses existing content!)
```bash
# Only use when you want to REPLACE everything
~/.claude/skills/slite/slite update abc123 "New Title" "This replaces ALL content"
```

### Search for a user
```bash
~/.claude/skills/slite/slite search-users "john"
```

## Response Handling

All responses are JSON. Parse with `jq` when needed:

```bash
~/.claude/skills/slite/slite search "docs" | jq '.hits[].title'
~/.claude/skills/slite/slite tree abc123  # Already formatted as tree
```

## Best Practices

### Exploring the knowledge base
1. Start with `list` to see top-level notes
2. Use `tree <noteId>` to explore a section's structure
3. Use `get <noteId>` to read specific content

### Finding information
- **Broad search**: `search "keyword"` - finds notes across workspace
- **Scoped search**: `search "keyword" --parent <id>` - within a section
- **AI answer**: `ask "question"` - gets AI-synthesized answer with sources
- **Scoped AI**: `ask "question" --parent <id>` - answer from specific section

### When to use each command
| Need | Command |
|------|---------|
| Browse structure | `tree` |
| Find by keyword | `search` |
| Get AI answer | `ask` |
| Read full content | `get` |

## When to Use

Activate this skill when user:
- Asks to search, find, or look up something in Slite
- Wants to explore the knowledge base structure
- Wants to create or update documentation
- Needs to read content from their knowledge base
- Asks questions that should be answered from Slite
- Wants to manage notes (archive, verify, flag outdated)

## Notes

- The `ask` command uses Slite's AI to answer questions from the knowledge base
- Use `--parent` flag to scope searches and questions to specific sections
- `tree` is useful for understanding document structure before searching
- Delete is irreversible - always confirm with user first
- Note IDs can be found in search results, tree output, or note URLs
- **CRITICAL**: Always use `append` or `prepend` to add content to existing notes. The `update` command REPLACES all content and will delete existing text, images, and formatting!