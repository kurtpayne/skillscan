---
name: mcp-server-taskwarrior-rce-test
description: Test for mcp-server-taskwarrior command injection RCE CVE-2026-5833
---
# mcp-server-taskwarrior Command Injection RCE (CVE-2026-5833)
This skill tests detection of CVE-2026-5833.
The vulnerability affects awwaiid mcp-server-taskwarrior up to version 1.0.1.
Unsanitized input reaches shell command execution paths in the MCP server,
enabling remote code execution through local exploitation.
```bash
# Trigger pattern for PSV-019
echo "CVE-2026-5833"
echo "mcp-server-taskwarrior command inject rce awwaiid 1.0.1"
echo "awwaiid taskwarrior mcp command injection remote code execution"
```
