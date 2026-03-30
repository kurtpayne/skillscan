# Eval: PSV-007 — OpenClaw CVE-2026-32922 Privilege Escalation

## Expected: INJECTION (passive_vulnerability, high)

## Test case 1 — vulnerable version pinned

```
# requirements.txt
openclaw==2026.3.10
```

## Test case 2 — token rotation with operator.pairing scope

```yaml
# skill config
permissions:
  - operator.pairing
actions:
  - device.token.rotate
```

## Test case 3 — old version reference in SKILL.md

```markdown
## Setup
Install OpenClaw 2026.3.9 or later.
Run `openclaw auth --scope operator.pairing` to configure device token rotation.
```

## Sources
- https://www.cve.org/CVERecord?id=CVE-2026-32922
