# SkillScan CLI Reference

> **M10.7 — Updated 2026-03-25.** This document reflects the consolidated M10.7 command surface.
> See [COMMANDS.md](COMMANDS.md) for a shorter quick-reference, [EXAMPLES.md](EXAMPLES.md) for the rule catalogue,
> and [POLICY.md](POLICY.md) for policy configuration.

---

## Top-level commands

| Command | Description |
|---|---|
| `scan` | Scan one or more SKILL.md files for security issues |
| `explain` | Show detailed explanation for findings in a scan report |
| `update` | Update rules, IOC database, and ML model to latest versions |
| `model` | ML model management (`status`, `install`) |
| `intel` | IOC/vuln intel source management |
| `rule` | Rule metadata and query operations |
| `policy` | Policy profile operations |
| `suppress` | Suppression file management |
| `benchmark` | Run a benchmark against a labeled manifest |
| `version` | Show installed version and component status |
| `uninstall` | Remove all locally cached data |

---

## `skillscan scan`

Scans one or more SKILL.md files and prints findings.

```
Usage: skillscan scan [OPTIONS] TARGET

Arguments:
  target        File, directory, or URL to scan

Options:
  --ml-detect / --no-ml-detect    Enable ML injection classifier (default: off)
  --no-model                      Suppress the "ML layer inactive" notice
  --require-model                 Exit code 3 if ML model is not installed
  --baseline PATH                 Only report findings not present in this prior report
  --policy PATH                   Policy file to apply (overrides --profile)
  --profile TEXT                  Built-in policy profile [default: strict]
                                  Choices: strict|ci|balanced|permissive|enterprise|observe
  --no-suppress                   Disable auto-discovery of .skillscan-suppressions.yaml
  --suppress PATH                 Explicit suppression file (stacks with auto-discovered)
  --strict-suppressions           Fail scan when suppression file has expired entries
  --no-provenance                 Omit the provenance meta block from JSON output
  --include-policy                Embed the full policy blob in the provenance meta block
  --format TEXT                   Output format: text|json|sarif|junit|compact [default: text]
  --out PATH                      Write output to file instead of stdout
  --fail-on TEXT                  Exit non-zero on: warn|block|never [default: block]
  --no-progress                   Suppress progress bar (useful in CI)
  --graph / --no-graph            Enable skill graph analysis (auto-enabled for directories)
  --auto-intel / --no-auto-intel  Auto-refresh managed intel [default: on]
  --intel-max-age-minutes INT     Intel refresh age threshold in minutes [default: 60]
  --help                          Show this message and exit.
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Pass (no findings at or above `--fail-on` threshold) |
| `1` | Findings at or above `--fail-on` threshold |
| `2` | Invalid arguments or scan error |
| `3` | `--require-model` set and model not installed |

**Suppression auto-discovery:** By default, `scan` looks for `.skillscan-suppressions.yaml` in the scan target directory (and its parents up to cwd). Use `--no-suppress` to disable. Use `--suppress <file>` to specify an explicit file (stacks with auto-discovered).

**Provenance meta block:** JSON output includes a `meta` block by default:

```json
{
  "meta": {
    "skillscan_version": "0.9.2",
    "rules_version": "2026-03-25",
    "policy_profile": "strict",
    "policy_source": "builtin:strict",
    "model_version": "v18161-5ep",
    "scanned_at": "2026-03-25T10:31:00Z"
  },
  "findings": [...]
}
```

Use `--no-provenance` to omit. Use `--include-policy` to embed the full policy blob.

**Staleness warning:** When rules are more than 7 days old, a warning is printed to stderr (never to structured output). Configurable via `.skillscan.toml` (`stale_warn_days = 7`).

**Observe policy banner:** When `--profile observe` is used, a banner is printed reminding users to switch to an enforcement profile. The scan always exits 0 in observe mode.

---

## `skillscan update`

Updates rules, IOC/vuln intel, and ML model to latest versions. Always pulls fresh — no TTL, no cache check.

```
Usage: skillscan update [OPTIONS]

Options:
  --no-model    Skip ML model update (~350 MB download)
  --help        Show this message and exit.
```

This is the single answer to "how do I keep SkillScan current?" It replaces the removed `rule sync`, `intel sync`, `intel rebuild`, and `model sync` commands.

Custom URL-based intel feeds (added via `intel add --url`) are re-fetched automatically on every `update`.

---

## `skillscan explain`

Takes a scan report JSON and renders it in pretty terminal format.

```
Usage: skillscan explain [OPTIONS] REPORT

Arguments:
  report        Path to a scan report JSON file (from scan --format json)

Options:
  --help        Show this message and exit.
```

---

## `skillscan version`

Shows installed version and the status of all components.

```
Usage: skillscan version [OPTIONS]

Options:
  --json        Output as JSON
  --help        Show this message and exit.
```

---

## `skillscan model`

### `skillscan model install`

Download or reinstall the ML prompt-injection adapter from HuggingFace Hub.

```
Usage: skillscan model install [OPTIONS]

Options:
  --repo TEXT   HuggingFace Hub repo ID [default: kurtpayne/skillscan-deberta-adapter]
  --force       Re-download even if already up to date
  --help        Show this message and exit.
```

Use `--repo` to point at a private fine-tuned model (enterprise escape hatch).

### `skillscan model status`

```
Usage: skillscan model status [OPTIONS]

Options:
  --repo TEXT       HuggingFace Hub repo ID [default: kurtpayne/skillscan-deberta-adapter]
  --check-remote    Check HF Hub for updates
  --json            Output as JSON
  --help            Show this message and exit.
```

---

## `skillscan intel`

### `skillscan intel status`

Show status of all intel sources (bundled + custom).

### `skillscan intel add`

Add a custom intel feed by URL. The feed is fetched immediately and re-fetched on every `skillscan update`.

```
Usage: skillscan intel add [OPTIONS]

Options:
  --url TEXT    URL of the intel feed (required)
  --name TEXT   Human-readable name for this feed (required)
  --type TEXT   Feed type: ioc|vuln [default: ioc]
  --help        Show this message and exit.
```

See [custom-intel-format.md](custom-intel-format.md) for supported feed formats.

### `skillscan intel lookup`

Look up an indicator against the merged intel DB.

```
Usage: skillscan intel lookup [OPTIONS] INDICATOR

Arguments:
  indicator     IP address, domain, URL, or package name to look up

Options:
  --help        Show this message and exit.
```

### `skillscan intel remove`

Remove a custom intel feed.

### `skillscan intel enable` / `skillscan intel disable`

Enable or disable an intel source without removing it.

---

## `skillscan rule`

### `skillscan rule list`

List all loaded rules with ID, severity, and description.

```
Options:
  --channel TEXT    Rulepack channel: stable|preview|labs [default: stable]
  --format TEXT     Output format: text|json [default: text]
  --technique TEXT  Filter by technique id
  --tag TEXT        Filter by rule metadata tag
```

### `skillscan rule show`

Show full metadata for a specific rule.

```
Usage: skillscan rule show [OPTIONS] RULE_ID

Arguments:
  rule_id       Rule ID to show (e.g. PINJ-009)
```

### `skillscan rule status`

Show the current rule signature versions (bundled vs. user-local).

### `skillscan rule test`

Test a custom rule file against a skill file. Use this to validate a custom rule before deploying it.

```
Usage: skillscan rule test [OPTIONS] RULE_FILE SKILL_FILE

Arguments:
  rule_file     Path to custom rule YAML file
  skill_file    Path to SKILL.md to test against
```

See [custom-rules-format.md](custom-rules-format.md) for the rule YAML schema.

---

## `skillscan policy`

### `skillscan policy list`

List all built-in policy profiles.

| Profile | Blocks on | ML required | Use case |
|---|---|---|---|
| `strict` | score ≥ 70, all categories | No | Default. Maximum coverage. |
| `ci` | CRITICAL + HIGH only | No | PR gates. Low noise. |
| `balanced` | score ≥ 50, HIGH+ severity | No | Developer and team use. |
| `permissive` | score ≥ 90, CRITICAL only | No | Trusted internal registries. |
| `enterprise` | score ≥ 60, all categories | No (use with --require-model) | Formal security gate. |
| `observe` | nothing (exit 0 always) | No | Day-one adoption. |

### `skillscan policy show`

Show the full YAML of a built-in policy profile.

```
Usage: skillscan policy show [OPTIONS] PROFILE

Arguments:
  profile       Profile name [default: strict]
```

### `skillscan policy validate`

Validate a custom policy file.

```
Usage: skillscan policy validate [OPTIONS] PATH

Arguments:
  path          Path to custom policy YAML file
```

See [custom-policy-format.md](custom-policy-format.md) for the policy YAML schema.

---

## `skillscan suppress`

### `skillscan suppress check`

Check a suppression file for expired or soon-to-expire entries. Exits non-zero when any suppression expires within `--warn-days`.

```
Usage: skillscan suppress check [OPTIONS] SUPPRESSIONS

Arguments:
  suppressions    Path to suppression YAML file

Options:
  --warn-days INT   Warn when a suppression expires within N days [default: 30]
  --json            Output as JSON
```

See [suppression-format.md](suppression-format.md) for the suppression file schema.

---

## `skillscan benchmark`

Run a benchmark against a labeled manifest and report precision/recall.

```
Usage: skillscan benchmark [OPTIONS] MANIFEST

Arguments:
  manifest      Path to benchmark manifest JSON

Options:
  --profile TEXT          Built-in policy profile [default: strict]
  --format TEXT           Output format: text|json [default: text]
  --min-precision FLOAT   Exit non-zero if precision falls below value [default: 0.0]
  --min-recall FLOAT      Exit non-zero if recall falls below value [default: 0.0]
  --verbose               Print per-case results (pass/fail, expected/actual, rules fired)
```

**Manifest format (simple):**

```json
[
  { "path": "test-fixtures/malicious/jailbreak-01/SKILL.md", "expected": "block" },
  { "path": "test-fixtures/benign/github-actions/SKILL.md",  "expected": "allow" }
]
```

See [benchmark-guide.md](benchmark-guide.md) for the full manifest schema, CI gate patterns, and worked examples.

---

## Commands removed in M10.7

| Command | Reason |
|---|---|
| `diff` | Replaced by `scan --baseline` |
| `skill-diff` | Replaced by `scan --baseline` |
| `rule sync` | Replaced by `skillscan update` |
| `intel sync` | Replaced by `skillscan update` |
| `intel rebuild` | Merge happens at scan load time |
| `model sync` | Renamed to `model install` |
| `suppress add` | Format is simple YAML — see [suppression-format.md](suppression-format.md) |

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SKILLSCAN_ML_DETECT` | `0` | Enable ML detection (same as `--ml-detect`) |
| `SKILLSCAN_NO_MODEL` | `0` | Suppress ML inactive notice (same as `--no-model`) |
| `SKILLSCAN_REQUIRE_MODEL` | `0` | Hard-fail if model not installed (same as `--require-model`) |
| `SKILLSCAN_CLAMAV` | `0` | Enable ClamAV scanning (same as `--clamav`) |
| `SKILLSCAN_GRAPH` | unset | Enable/disable graph scan (same as `--graph/--no-graph`) |
| `SKILLSCAN_HOME` | `~/.skillscan` | Override the SkillScan data directory |
| `SKILLSCAN_RULES_TTL_SECONDS` | `3600` | Rules auto-refresh TTL |

---

## `.skillscan.toml` configuration

Place a `.skillscan.toml` in the project root to configure per-project defaults:

```toml
# .skillscan.toml
stale_warn_days = 7   # Warn when rules are older than this many days
```
