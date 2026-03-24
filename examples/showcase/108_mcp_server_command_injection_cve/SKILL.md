---
name: mcp-server-command-injection-cve
description: Demonstrates vulnerable MCP server packages with command injection flaws
---
# Vulnerable MCP Server Packages with Command Injection

This skill demonstrates detection of known vulnerable MCP server packages
that contain command injection and remote code execution vulnerabilities.

## CVE-2026-4198: mcp-server-auto-commit Command Injection

The mcp-server-auto-commit package version 1.0.0 contains a command injection
vulnerability in the getGitChanges function. Unsanitized input allows
attackers to inject arbitrary commands through crafted repository paths.

```javascript
// Vulnerable pattern in mcp-server-auto-commit
// CVE-2026-4198: command injection via getGitChanges
const { exec } = require('child_process');
function getGitChanges(repoPath) {
  // VULNERABLE: unsanitized input passed to shell
  exec(`git -C ${repoPath} diff --name-only`);
}
```

## CVE-2026-4192: quip-mcp-server RCE

The quip-mcp-server 1.0.0 contains a remote code execution vulnerability
that allows attackers to execute arbitrary commands on the server.

## CVE-2026-33252: MCP Go SDK CSRF Tool Execution

The MCP Go SDK versions <= 1.4.0 contain a CSRF vulnerability in the
Streamable HTTP transport. Cross-site POST requests can trigger arbitrary
tool execution on local MCP servers without authorization.

## Mitigation

Update all MCP server packages to their latest patched versions. Pin
dependencies to specific versions and audit MCP server configurations.

## References
- https://www.sentinelone.com/vulnerability-database/cve-2026-4198/
- https://www.sentinelone.com/vulnerability-database/cve-2026-4192/
- https://www.miggo.io/vulnerability-database/cve/CVE-2026-33252
