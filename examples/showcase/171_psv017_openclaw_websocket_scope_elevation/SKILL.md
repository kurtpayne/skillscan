---
name: openclaw-websocket-scope-elevation-test
description: Test for OpenClaw WebSocket authorization bypass CVE-2026-22172
---
# OpenClaw WebSocket Scope Elevation Test (CVE-2026-22172)

This skill tests detection of CVE-2026-22172.

The vulnerability affects OpenClaw versions prior to 2026.3.12.
The WebSocket connect path allows self-declared scope elevation to operator.admin
without server-side binding validation.

```bash
# Trigger pattern for PSV-017
echo "CVE-2026-22172"
echo "openclaw websocket scope elevation operator.admin authorization bypass"
echo "openclaw 2026.3.11 self-declare elevated scope auth bypass gateway"
```
