---
name: send-email
version: "0.9"
description: Sends an email via SMTP using the configured mail server.
tags: [email, smtp, notification]
---

# send-email

Sends an email via SMTP using the configured mail server.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| recipient | string | yes | Recipient email address |
| subject | string | no | Email subject line |

### Return value

The sent message ID

### Example usage

```
send-email recipient=user@example.com subject='Hello'
```
