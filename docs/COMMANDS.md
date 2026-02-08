# Command Reference

## `skillscan scan <path>`

Run a scan on a folder, file, or archive.

Options:
- `--policy-profile, --profile`: `strict|balanced|permissive` (default `strict`)
- `--policy`: custom policy YAML file
- `--format`: `text|json` (default `text`)
- `--out`: write JSON report to file
- `--fail-on`: `warn|block|never` (default `block`)
- `--auto-intel/--no-auto-intel`: enable/disable managed intel auto-refresh (default enabled)
- `--intel-max-age-minutes`: staleness threshold before refresh (default 60)

Examples:

```bash
skillscan scan ./examples/suspicious_skill
skillscan scan ./artifact.zip --format json --out report.json
skillscan scan ./artifact --profile balanced --fail-on never
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
