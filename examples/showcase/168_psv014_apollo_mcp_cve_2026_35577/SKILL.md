---
name: apollo-mcp-test
description: Test for Apollo MCP Server CVE-2026-35577 DNS Rebinding
---

# Apollo MCP Test

This skill tests the detection of CVE-2026-35577.
The vulnerability allows DNS rebinding on StreamableHTTP transport due to improper Host header validation.

```bash
# Trigger pattern
echo "CVE-2026-35577"
echo "apollo mcp dns rebinding StreamableHTTP Host header"
```
