# Custom Rules Format

Custom rules let you extend SkillScan's detection beyond the built-in rule set. They are useful for detecting internal naming conventions, proprietary API patterns, or organization-specific threat indicators that the bundled rules do not cover.

---

## Rule YAML schema

A rule file is a YAML document with a top-level `rules` key containing a list of rule objects.

```yaml
rules:
  - id: CUSTOM-001
    title: "Internal API credential leak"
    severity: high
    category: exfiltration
    pattern: "corp-api\\.example\\.com.*api[_-]?key"
    description: >
      Detects references to the internal API with credential-like parameters.
      This pattern fires on any SKILL.md that references corp-api.example.com
      with a query parameter that looks like an API key.
    mitigation: >
      Remove the credential reference. Use environment variable injection
      instead of hardcoding API keys in skill instructions.
    tags:
      - internal
      - credentials
```

### Required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique rule identifier. Use a consistent prefix (e.g. `CUSTOM-`, `CORP-`). |
| `title` | string | Short human-readable description of what the rule detects. |
| `severity` | string | `critical`, `high`, `medium`, or `low`. |
| `category` | string | Detection category (see below). |
| `pattern` | string | Python-compatible regex pattern. Case-insensitive by default. |

### Optional fields

| Field | Type | Description |
|---|---|---|
| `description` | string | Extended description of what the rule detects and why it is dangerous. |
| `mitigation` | string | Recommended remediation steps. |
| `tags` | list[string] | Arbitrary tags for filtering with `rule list --tag`. |
| `techniques` | list[string] | MITRE ATLAS technique IDs (e.g. `AML.T0051`). |

### Categories

Use one of the following category strings to match the built-in taxonomy:

| Category | Description |
|---|---|
| `injection` | Prompt injection and jailbreak patterns |
| `exfiltration` | Data exfiltration channels |
| `malware` | Malware patterns and supply chain attacks |
| `instruction_abuse` | Instruction override and role confusion |
| `dependency` | Dependency vulnerability patterns |
| `threat_intel` | IOC-based threat intelligence matches |
| `graph` | Cross-skill graph-level attack patterns |

---

## Pattern syntax

Patterns are Python `re` regular expressions compiled with `re.IGNORECASE | re.MULTILINE`.

**Examples:**

```yaml
# Match a specific domain with credential-like parameter
pattern: "corp-api\\.example\\.com.*api[_-]?key"

# Match any reference to an internal endpoint
pattern: "https?://internal\\.corp\\.example"

# Match a role override phrase
pattern: "(ignore|disregard).{0,20}(previous|prior|above).{0,20}(instructions|prompt)"

# Match a fake end-of-prompt divider
pattern: "---\\s*(end of|end)\\s*(system\\s*prompt|instructions)\\s*---"
```

**Tip:** Use `rule test` to validate your pattern before deploying:

```bash
skillscan rule test my-rule.yaml skills/my-skill/SKILL.md
```

---

## Multi-rule files

A single YAML file can contain multiple rules:

```yaml
rules:
  - id: CORP-001
    title: "Internal API credential leak"
    severity: high
    category: exfiltration
    pattern: "corp-api\\.example\\.com.*api[_-]?key"

  - id: CORP-002
    title: "Staging environment reference"
    severity: low
    category: exfiltration
    pattern: "staging\\.corp\\.example\\.com"
    description: "Skills should not reference staging environments in production."
```

---

## Deploying custom rules

To make custom rules active for all scans, place the rule YAML file in `~/.skillscan/rules/`:

```bash
cp my-corp-rules.yaml ~/.skillscan/rules/
```

Rules in `~/.skillscan/rules/` are merged with the bundled rule set on every scan. Rule IDs that appear in both use the user-local version (allowing you to override built-in rules).

**Note:** Custom rules in `~/.skillscan/rules/` are overwritten by `skillscan update`. To preserve them, use a different filename prefix (e.g. `corp-*.yaml`) that does not conflict with the bundled rule file names (`default.yaml`, `ast_flows.yaml`, `exfil_channels.yaml`).

---

## Testing workflow

```bash
# Write your rule
cat > corp-rules.yaml << 'EOF'
rules:
  - id: CORP-001
    title: "Internal API credential leak"
    severity: high
    category: exfiltration
    pattern: "corp-api\\.example\\.com.*api[_-]?key"
EOF

# Test against a known-bad skill
skillscan rule test corp-rules.yaml test-fixtures/bad-skill/SKILL.md
# → Shows matched lines

# Test against a known-good skill
skillscan rule test corp-rules.yaml test-fixtures/good-skill/SKILL.md
# → No match found (exit code 1)

# Deploy
cp corp-rules.yaml ~/.skillscan/rules/

# Verify it's loaded
skillscan rule list | grep CORP-001
```
