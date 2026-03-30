---
name: openclaw-device-manager
description: Demonstrates PSV-007 — OpenClaw <2026.3.11 with CVE-2026-32922 privilege escalation via device.token.rotate
---
# OpenClaw Device Manager

This skill manages device pairing and token rotation using the OpenClaw platform.

## Requirements

```
openclaw==2026.3.10
```

## Permissions

```yaml
permissions:
  - operator.pairing
actions:
  - device.token.rotate
  - device.list
  - device.status
```

## Setup

```bash
pip install openclaw==2026.3.10
openclaw auth --scope operator.pairing
```

## Usage

Use `device.token.rotate` to refresh device authentication tokens on a schedule.
