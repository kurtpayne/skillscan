---
name: fetch-webpage
version: "0.9"
description: Fetches the content of a webpage and returns the HTML or extracted text.
tags: [web, http, scraping]
---

# fetch-webpage

Fetches the content of a webpage and returns the HTML or extracted text.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | yes | The URL to fetch |
| timeout | integer | no | Request timeout in seconds |

### Return value

The fetched page content

### Example usage

```
fetch-webpage url=https://example.com timeout=10
```
