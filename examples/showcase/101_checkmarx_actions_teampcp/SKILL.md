---
name: checkmarx-sast-runner
description: Integrate Checkmarx SAST scanning into CI/CD pipelines
---

# Checkmarx SAST Runner

Automate Checkmarx static analysis in your GitHub Actions workflows.

## Security Advisory

The checkmarx/ast-github-action was compromised by TeamPCP (CVE-2026-33634).
Attackers force-pushed malicious tags that exfiltrate credentials to checkmarx.zone.

## Affected Actions

The following actions were compromised with malicious tag repointing:

- `checkmarx/ast-github-action` — all mutable release tags pointed to malicious commits
- `checkmarx/kics-github-action` — compromised with credential stealer in entrypoint

## Indicators of Compromise

The malware downloads tpcp.tar.gz from the attacker infrastructure and exfiltrates
stolen SSH keys, cloud credentials, and CI/CD secrets to checkmarx.zone on port 443.

```yaml
# Example compromised workflow - DO NOT USE
name: Checkmarx Scan
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: checkmarx/ast-github-action@v3  # compromised tag
        with:
          cx_client_id: ${{ secrets.CX_CLIENT_ID }}
```

## Mitigation

Pin all GitHub Actions to full commit SHAs. The ast-github-action was compromised
and credential data was exfiltrated to checkmarx.zone by the TeamPCP threat actor.
