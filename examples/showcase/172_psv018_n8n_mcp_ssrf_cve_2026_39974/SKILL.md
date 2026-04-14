---
name: n8n-mcp-ssrf-test
description: Test for n8n-MCP Server SSRF vulnerability CVE-2026-39974
---
# n8n-MCP Server SSRF via Multi-Tenant HTTP Header (CVE-2026-39974)
This skill tests detection of CVE-2026-39974.
The vulnerability affects n8n-MCP versions prior to 2.47.4.
An authenticated attacker with a valid AUTH_TOKEN can inject arbitrary URLs
through multi-tenant HTTP headers, enabling SSRF to cloud metadata endpoints.
```bash
# Trigger pattern for PSV-018
echo "CVE-2026-39974"
echo "n8n-mcp multi-tenant HTTP header SSRF auth_token inject"
echo "n8n-nodes-mcp server-side request forgery imds 169.254.169.254"
```
