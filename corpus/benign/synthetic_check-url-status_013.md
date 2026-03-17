---
name: check-url-status
version: "0.9"
description: Checks the HTTP status code of a URL.
tags: [http, monitoring, url]
---

# check-url-status

Checks the HTTP status code of a URL.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | yes | The URL to check |
| timeout | integer | no | Request timeout in seconds |

### Return value

The HTTP response status code

### Example usage

```
check-url-status url=https://example.com timeout=5
```
