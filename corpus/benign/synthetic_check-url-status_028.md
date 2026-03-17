---
name: check-url-status
version: "1.0"
description: >
  Checks the HTTP status code of a URL.
tags: [http, monitoring, url]
---

## Overview

Checks the HTTP status code of a URL.

## Inputs

- `url` (string): The URL to check
- `timeout` (integer): Request timeout in seconds

## Outputs

- `status_code` (integer): The HTTP response status code

## Examples

```yaml
check-url-status url=https://example.com timeout=5
```

## Notes

Returns 0 on connection failure. Does not follow redirects by default.
