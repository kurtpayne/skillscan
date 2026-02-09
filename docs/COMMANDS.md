# Command Reference

## `skillscan scan <path>`

Run a scan on a folder, file, archive, or URL.

Options:
- `--policy-profile, --profile`: `strict|balanced|permissive` (default `strict`)
- `--policy`: custom policy YAML file
- `--format`: `text|json` (default `text`)
- `--out`: write JSON report to file
- `--fail-on`: `warn|block|never` (default `block`)
- `--auto-intel/--no-auto-intel`: enable/disable managed intel auto-refresh (default enabled)
- `--intel-max-age-minutes`: staleness threshold before refresh (default 60)
- `--url-max-links`: max followed links for URL targets (default 25)
- `--url-same-origin-only/--no-url-same-origin-only`: link-following origin policy (default same-origin only)
- `--ai-assist/--no-ai-assist`: enable optional AI semantic risk checks (default disabled)
- `--ai-provider`: `auto|openai|anthropic|gemini|openai_compatible` (default `auto`)
- `--ai-model`: model id override (provider-specific)
- `--ai-base-url`: custom provider base URL (self-hosted/proxy)
- `--ai-timeout-seconds`: AI request timeout (default 20)
- `--ai-required/--ai-optional`: fail scan if AI assist fails (default optional)
- `--ai-report-out`: write raw AI JSON output to file

Examples:

```bash
skillscan scan ./examples/suspicious_skill
skillscan scan ./artifact.zip --format json --out report.json
skillscan scan ./artifact --profile balanced --fail-on never
skillscan scan "https://github.com/blader/humanizer/blob/main/SKILL.md?plain=1"
skillscan scan ./examples/showcase/20_ai_semantic_risk --ai-assist --ai-provider openai --fail-on never
```

## `skillscan explain <report.json>`

Render a previously generated JSON report in pretty terminal format.

```bash
skillscan explain ./report.json
```

## `skillscan policy show-default`

Print a built-in policy profile.

```bash
skillscan policy show-default --profile strict
```

## `skillscan policy validate <policy.yaml>`

Validate a custom policy file.

```bash
skillscan policy validate ./examples/policies/strict_custom.yaml
```

## `skillscan intel ...`

Manage local intel sources.

Commands:
- `status`
- `list`
- `add <path> --type ioc|vuln|rules --name <name>`
- `remove <name>`
- `enable <name>`
- `disable <name>`
- `rebuild`
- `sync [--force] [--max-age-minutes N]`

## `skillscan uninstall`

Uninstall local runtime artifacts.

Options:
- `--keep-data`: preserve `~/.skillscan` data files.

## `skillscan version`

Print installed version.
