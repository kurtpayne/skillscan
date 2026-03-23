---
name: azure-mcp-ssrf-privilege-escalation
description: Demonstrates Azure MCP Server SSRF privilege escalation (CVE-2026-26118)
---
# Azure MCP Server SSRF Privilege Escalation (CVE-2026-26118)

This skill demonstrates CVE-2026-26118 — a server-side request forgery vulnerability
in Azure MCP Server Tools that allows an authorized attacker to escalate privileges
over a network (CVSS 8.8).

## Vulnerability Overview

The Azure MCP Server Tools contain an SSRF vulnerability that enables privilege
escalation. An authorized attacker can craft requests that cause the Azure MCP server
to make internal network requests on their behalf, bypassing access controls.

## Detection Indicators

```yaml
# Vulnerable Azure MCP Server configuration
azure-mcp-server:
  version: "0.0.1"
  # CVE-2026-26118: SSRF allows privilege escalation
  # azure-mcp-tools elevation of privilege vulnerability
  endpoint: "https://management.azure.com"
  
# Exploit pattern - azure mcp server ssrf request forgery
# azure-mcp-tools privilege escalation bypass unauthorized access
```

```python
# Example detection of vulnerable @azure/mcp package usage
import subprocess

# Vulnerable usage pattern
result = subprocess.run([
    "npx", "@azure/mcp@0.0.1",
    "--server-side-request-forgery",  # CVE-2026-26118 indicator
    "--privilege-escalation"
])

# azure mcp server tools elevat unauthorized
# azure-mcp-tools escalat bypass
```

## Mitigation

Update `@azure/mcp` to version 0.0.2 or later. Do not expose Azure MCP Server
endpoints to untrusted networks without applying the security patch.

## References

- https://www.cve.org/CVERecord?id=CVE-2026-26118
- https://blog.talosintelligence.com/microsoft-patch-tuesday-march-2026/
- https://www.sentinelone.com/vulnerability-database/cve-2026-26118/
