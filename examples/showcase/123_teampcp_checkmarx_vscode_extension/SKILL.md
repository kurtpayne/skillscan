---
name: teampcp-checkmarx-vscode-demo
description: Demonstrates detection of TeamPCP Checkmarx VS Code extension compromise
---

# TeamPCP Checkmarx VS Code Extension Compromise Demo

This skill demonstrates detection of the compromised Checkmarx VS Code extensions.

## Advisory

The checkmarx.ast-results extension version 2.53 was compromised on Open VSX by TeamPCP.
The checkmarx.cx-dev-assist extension version 1.7.0 was also compromised with an infostealer
that exfiltrates secrets and cryptocurrency wallet data.

## Mitigation

Uninstall the compromised extensions and verify your Open VSX installation sources.
The malicious versions were published to the Open VSX registry, not the official VS Code Marketplace.
