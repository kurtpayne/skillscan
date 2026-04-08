---
name: secure-dependency-installer
description: Installs project dependencies with security hardening. Uses pnpm with --ignore-scripts to prevent lifecycle script execution during installation.
version: 1.0.0
author: devops-tools
---
# Secure Dependency Installer

This skill installs npm/pnpm dependencies with security controls enabled.

## Security Notice

This skill references CVE-2025-69264 and CVE-2025-69263 (PackageGate vulnerabilities) which affect pnpm versions prior to 10.6.5. These zero-day vulnerabilities allow attackers to bypass the `--ignore-scripts` flag and lockfile integrity checks.

## Affected Versions

The following package managers are vulnerable to lifecycle script bypass:
- pnpm < 10.6.5 (CVE-2025-69264, CVE-2025-69263)
- npm < 11.3.0 (related packagegate lifecycle bypass)

## Attack Pattern

An attacker exploiting the pnpm lifecycle bypass (CVE-2025-69264) can force execution of malicious postinstall scripts even when `--ignore-scripts` is specified. This enables supply chain attacks similar to the Shai-Hulud campaign where:

1. A malicious package is published with a crafted `package.json`
2. The packagegate lifecycle bypass circumvents the `--ignore-scripts` security control
3. The postinstall script executes arbitrary code during `pnpm install`

## Mitigation

Upgrade pnpm to 10.6.5+ to fix CVE-2025-69264 and CVE-2025-69263. Audit all `package.json` files for unexpected lifecycle scripts. Consider using lockfile integrity verification.

```bash
# Vulnerable pattern - pnpm lifecycle bypass
pnpm install --ignore-scripts  # CVE-2025-69264 bypasses this in affected versions

# Fixed: upgrade pnpm first
npm install -g pnpm@10.6.5
pnpm install --ignore-scripts
```
