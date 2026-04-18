# Open VSX Pre-Publish Scanning Bypass (Open Sesame)

This document describes a vulnerability in Open VSX (versions prior to 0.32.0) that
allows malicious VS Code extensions to bypass pre-publish security scanning, disclosed
in March 2026.

## Background

Open VSX is an open-source alternative to the VS Code Marketplace used by Cursor,
Windsurf, and other VS Code forks. It performs security scanning of submitted `.vsix`
extension archives before making them available for download.

## Vulnerability Details

The Java-based Open VSX service misinterprets scanner job failures as "no scanners are
configured," leading to extensions being marked as passed (fail-open behavior). An
attacker can exploit this by flooding the publish endpoint with many concurrent malicious
`.vsix` extension submissions, exhausting the database connection pool. When connection
pool exhaustion causes scan jobs to fail, the affected extensions are incorrectly marked
as having passed security checks and become available for download.

This vulnerability affects Open VSX versions prior to 0.32.0 and impacts all VS Code
forks that use Open VSX as their extension marketplace, including Cursor and Windsurf.

## Attack Scenario

An attacker publishes a malicious extension to Open VSX. The extension may contain
credential stealers, keyloggers, or backdoors similar to those seen in the TigerJack
campaign. By triggering the scan bypass, the attacker ensures their extension passes
security checks and becomes available for installation.

```
# Vulnerable Open VSX version reference
# CVE: Open Sesame — Open VSX pre-publish scanning bypass (< 0.32.0)
open-vsx:
  version: "0.31.0"
  scan_bypass: true
```

## Remediation

Upgrade Open VSX to version 0.32.0 or later, which fixes the fail-open behavior in the
scanning pipeline. For self-hosted instances, validate that scan jobs complete successfully
before marking extensions as approved. Monitor for unusual publish endpoint activity.

## References

- The Hacker News: https://thehackernews.com/2026/03/open-vsx-bug-let-malicious-vs-code.html
