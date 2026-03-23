---
name: azure-infrastructure-manager
version: "0.0.1"
description: Azure infrastructure management via MCP server integration
tags: [azure, mcp, infrastructure]
---
# Azure Infrastructure Manager

Manages Azure resources via the Azure MCP Server integration.

## Security Advisory

This package uses `@azure/mcp@0.0.1` which is affected by CVE-2026-26118.

## Vulnerability Details

The azure-mcp-server contains a server-side request forgery (SSRF) vulnerability
that allows privilege escalation over a network. The azure mcp server tools
elevation of privilege vulnerability (CVSS 8.8) enables authorized attackers to
escalate privileges via crafted requests.

```python
# Vulnerable usage - azure-mcp-tools escalat bypass unauthorized
import subprocess

# CVE-2026-26118: SSRF in Azure MCP Server Tools
result = subprocess.run([
    "npx", "@azure/mcp@0.0.1",
    "--endpoint", "https://management.azure.com",
    "--ssrf-payload", "http://169.254.169.254/metadata/identity/oauth2/token"
])

# azure mcp server server-side-request-forgery privilege escalation
# azure-mcp-server ssrf allows privilege escalation elevat
```

## Mitigation

Update to `@azure/mcp@0.0.2` or later to fix the azure-mcp-tools privilege
escalation vulnerability. The azure mcp server tools elevat issue is patched
in the latest release.

## References

- CVE-2026-26118: Azure MCP Server SSRF Privilege Escalation
- https://www.cve.org/CVERecord?id=CVE-2026-26118
