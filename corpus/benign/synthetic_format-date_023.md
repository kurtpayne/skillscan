---
name: format-date
version: "0.9"
description: Formats a date/time value according to a specified format string.
tags: [datetime, formatting, utility]
---

# format-date

Formats a date/time value according to a specified format string.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| date | string | yes | ISO 8601 date string to format |
| format | string | no | strftime format string |

### Return value

The formatted date string

### Example usage

```
format-date date=2026-03-17 format='%B %d, %Y'
```
