---
name: mcp-go-sdk-dns-rebinding-test
description: Test for MCP Go SDK DNS rebinding vulnerability CVE-2026-34742
---
# MCP Go SDK DNS Rebinding Test (CVE-2026-34742)

This skill tests detection of CVE-2026-34742 (GHSA-xw59-hvm2-8pj6).

The vulnerability affects github.com/modelcontextprotocol/go-sdk versions prior to v1.4.0.
HTTP-based MCP servers do not enable DNS rebinding protection by default on localhost.

```bash
# Trigger pattern for PSV-015
echo "CVE-2026-34742"
echo "modelcontextprotocol/go-sdk dns rebinding localhost vulnerability"
echo "MCP go-sdk 0.3.0 dns rebinding tool execution bypass"
```
