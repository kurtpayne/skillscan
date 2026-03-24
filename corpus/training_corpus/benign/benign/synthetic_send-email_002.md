---
name: send-email
version: "1.0"
description: >
  Sends an email via SMTP using the configured mail server.
tags: [email, smtp, notification]
---

## Overview

Sends an email via SMTP using the configured mail server.

## Inputs

- `recipient` (string): Recipient email address
- `subject` (string): Email subject line

## Outputs

- `message_id` (string): The sent message ID

## Examples

```yaml
send-email recipient=user@example.com subject='Hello'
```

## Notes

Requires SMTP credentials in environment variables.
