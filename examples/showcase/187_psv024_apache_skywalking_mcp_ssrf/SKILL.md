# Apache SkyWalking MCP SSRF via SW-URL Header (CVE-2026-34476)

This document describes CVE-2026-34476, a Server-Side Request Forgery (SSRF) vulnerability
in Apache SkyWalking MCP version 0.1.0, disclosed April 13, 2026.

## Background

Apache SkyWalking MCP is an MCP server that exposes SkyWalking observability data
(traces, logs, metrics, topology, alarms, events) through MCP tools. Version 0.1.0
contains an SSRF vulnerability that allows attackers to forge requests to internal
resources by manipulating the SW-URL header.

## Vulnerability Details

CVE-2026-34476 affects Apache SkyWalking MCP version 0.1.0. The MCP server fails to
validate or sanitize the SW-URL header value before using it to construct backend requests.
An attacker with network access can supply a crafted SW-URL header pointing to internal
services, cloud metadata endpoints (e.g., `http://169.254.169.254/`), or other restricted
resources.

A companion vulnerability, CVE-2026-34884, also affects version 0.1.0 and covers SSRF
via the `set_skywalking_url` MCP tool as well as GraphQL expression injection in the
MCP server.

## Affected Configuration

```yaml
# Example vulnerable configuration referencing Apache SkyWalking MCP 0.1.0
# CVE-2026-34476: SSRF via SW-URL header in apache/skywalking-mcp
mcp_server:
  type: skywalking-mcp
  version: "0.1.0"
  endpoint: "http://skywalking-oap:12800"
```

## Remediation

Upgrade to Apache SkyWalking MCP version 0.2.0 or later, which adds validation for
tool configuration properties and fixes the SW-URL header SSRF. Restrict network access
to the SkyWalking MCP server to trusted hosts only.

## References

- CVE-2026-34476: https://www.sentinelone.com/vulnerability-database/cve-2026-34476/
- Apache Security Advisory: https://lists.apache.org/thread/399k1gnfspowl0989z11l73kk1hqd5sp
- OSS-Sec: https://seclists.org/oss-sec/2026/q2/116
