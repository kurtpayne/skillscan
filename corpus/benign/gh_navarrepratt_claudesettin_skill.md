---
name: cw-scaffold
version: "1.0"
description: Add components to existing repos or generate archetypes locally. Use when adding GitHub workflows, CODEOWNERS, Helm c...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: NavarrePratt/claude-settings
# corpus-url: https://github.com/NavarrePratt/claude-settings/blob/HEAD/skills/cw-scaffold/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# CW Scaffolding

Add standardized components to existing repositories or generate complete project archetypes locally.

## When to Use This Skill

Use this skill when:
- Adding CODEOWNERS to a repository
- Setting up GitHub workflows (linting, dependency updates, PR review)
- Adding Backstage catalog configuration
- Creating Helm charts
- Generating a new project structure locally

## Instructions

### Step 1: Understand the Request

Determine what the user wants:
- **Component**: Add a specific feature to an existing repo
- **Archetype**: Generate a complete project structure

**Available Components:**

| Group | Component | Purpose |
|-------|-----------|---------|
| backstage | catalog-yaml-component | Register as Backstage Component |
| backstage | catalog-yaml-location | Register as Backstage Location |
| backstage | catalog-yaml-system | Register as Backstage System |
| github | codeowners | Define code ownership |
| github | workflow-claude-review-prs | AI-powered PR review |
| github | workflow-close-stale-prs | Auto-close stale PRs |
| github | workflow-megalinter | Comprehensive linting |
| github | workflow-renovate | Automated dependency updates |
| helm | chart-basic | Kubernetes Helm chart |

**Available Archetypes:**

| Archetype | Purpose |
|-----------|---------|
| blank-repo | Minimal starter with CODEOWNERS and Backstage |
| go-http-service | Production-ready Go HTTP service |

### Step 2: Pre-flight Checks

```bash
cw version  # Verify CLI installed
pwd         # Confirm in correct directory (for components)
```

For components, user should be in the repository root.

### Step 3: Component Generation

**IMPORTANT: This modifies files in the repository. Get user confirmation before running.**

**Interactive mode:**
```bash
cw scaffold generate -c
```

**With specific version:**
```bash
cw scaffold generate -c --version v2.5.0
```

**Non-interactive mode (for automation):**

Create config.yaml:
```yaml
componentGroup: github
componentName: codeowners
inputs:
  github_team_name: your-team
```

Run:
```bash
cw scaffold generate --config config.yaml --skip-pr
```

### Step 4: Archetype Generation

**Interactive mode:**
```bash
cw scaffold generate -a
```

This prompts for:
- Archetype selection
- Output directory
- Project-specific inputs

### Step 5: Post-Generation

After generation:

1. **Review generated files:**
   ```bash
   git status
   git diff
   ```

2. **Commit changes:**
   Use `/commit` skill for proper commit message

3. **Create PR if needed:**
   The CLI may offer to create a PR automatically

## Common Workflows

### Add CODEOWNERS

```bash
cd your-repo
cw scaffold generate -c
# Select: github -> codeowners
# Provide: team name
```

### Add Megalinter

```bash
cd your-repo
cw scaffold generate -c
# Select: github -> workflow-megalinter
```

### Add Renovate for Dependency Updates

```bash
cd your-repo
cw scaffold generate -c
# Select: github -> workflow-renovate
```

### Generate Go Service Locally

```bash
cw scaffold generate -a
# Select: go-http-service
# Specify: output directory
# Provide: project name, team, etc.
```

## Validation

To validate templates (useful for template maintainers):

```bash
cw scaffold validate <path> -c   # Validate as component
cw scaffold validate <path> -a   # Validate as archetype
cw scaffold validate <path> -f   # Fail fast on first error
```

## Troubleshooting

**Component not found:**
```bash
rm -rf ~/.cw/cli/cached-templates/
cw scaffold generate -c  # Re-fetches templates
```

**Wrong version:**
```bash
cw scaffold generate -c --version v2.5.0
```

**Test local templates:**
```bash
cw scaffold generate -c --path /path/to/local/repo-templates
```

**View available components/archetypes:**
```bash
cw scaffold info -c
cw scaffold info -a
```