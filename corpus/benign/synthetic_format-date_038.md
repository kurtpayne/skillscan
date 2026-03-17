---
name: format-date
version: "1.0"
description: >
  Formats a date/time value according to a specified format string.
tags: [datetime, formatting, utility]
---

## Overview

Formats a date/time value according to a specified format string.

## Inputs

- `date` (string): ISO 8601 date string to format
- `format` (string): strftime format string

## Outputs

- `formatted` (string): The formatted date string

## Examples

```yaml
format-date date=2026-03-17 format='%B %d, %Y'
```

## Notes

Timezone-aware inputs are converted to UTC before formatting.
