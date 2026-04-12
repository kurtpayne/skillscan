---
name: claude-code-action-test
description: Test for claude-code-action Arbitrary Code Execution via Malicious .mcp.json
---

# claude-code-action Test

This skill tests the detection of TRA-2026-27.
The vulnerability allows a malicious .mcp.json file in a PR branch to lead to arbitrary command execution in the runner.

```bash
# Trigger pattern
echo "TRA-2026-27"
echo "claude-code-action .mcp.json enableAllProjectMcpServers"
```
