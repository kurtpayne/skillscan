# nginx-ui MCP Endpoint Authentication Bypass (CVE-2026-33032)
This document covers CVE-2026-33032, a critical authentication bypass in nginx-ui
versions 2.3.5 and prior, actively exploited in the wild since March 2026.

## Vulnerability Details

nginx-ui is a popular open-source web interface for managing Nginx servers. Its
MCP (Model Context Protocol) integration exposes two HTTP endpoints:

- `/mcp` — requires IP whitelisting AND authentication (AuthRequired() middleware)
- `/mcp_message` — only applies IP whitelisting (default empty = allow all)

The `/mcp_message` endpoint lacks authentication entirely. Because the default
IP whitelist is empty, which the middleware treats as "allow all", any network
attacker can invoke all MCP tools without authentication.

## Impact

An unauthenticated attacker can:
- Restart the nginx service
- Create, modify, and delete nginx configuration files
- Trigger automatic configuration reloads
- Achieve complete nginx service takeover

CVSS 9.8 (CRITICAL), CWE-306 (Missing Authentication for Critical Function).
Over 2,600 instances actively exploited since March 2026.

## Affected Versions

nginx-ui versions 2.3.5 and prior (all versions up to and including 2.3.5).
No official patch available at time of publication.

## Mitigation

Disable the MCP integration endpoint or restrict `/mcp_message` to trusted IPs
via firewall rules immediately. Monitor for unauthorized nginx configuration
changes. Consider blocking external access to the nginx-ui management interface.

## References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33032
- GitHub Advisory (GHSA-h6c2-x2m2-mwhf): https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-h6c2-x2m2-mwhf
- The Hacker News: https://thehackernews.com/2026/04/critical-nginx-ui-vulnerability-cve.html
- Field Effect: https://fieldeffect.com/blog/critical-nginx-ui-vulnerability
- Pluto Security: https://pluto.security/blog/mcp-bug-nginx-security-vulnerability-cvss-9-8/
