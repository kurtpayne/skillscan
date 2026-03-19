# Audit Logging
Implement tamper-evident audit logs for security-sensitive operations.

## What to log
- Authentication events (login, logout, failed attempts, MFA)
- Authorization decisions (access granted/denied)
- Data access (who read what, when)
- Configuration changes (who changed what setting, before/after values)
- Privilege escalation

## Log format
Use structured logging (JSON) with consistent fields:
```json
{
  "timestamp": "2026-03-19T14:23:01Z",
  "event_type": "auth.login.success",
  "user_id": "usr_abc123",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "session_id": "sess_xyz789"
}
```

## Tamper protection
Ship logs to an append-only log aggregation service (Splunk, Datadog, CloudWatch Logs) immediately. Don't rely solely on local log files — they can be modified by an attacker who gains system access.

## Retention
Retain security audit logs for at least 1 year (SOC 2 requirement). Encrypt logs at rest.
