---
name: fetch-webpage
version: "1.0"
description: >
  Fetches the content of a webpage and returns the HTML or extracted text.
tags: [web, http, scraping]
---

## Overview

Fetches the content of a webpage and returns the HTML or extracted text.

## Inputs

- `url` (string): The URL to fetch
- `timeout` (integer): Request timeout in seconds

## Outputs

- `content` (string): The fetched page content

## Examples

```yaml
fetch-webpage url=https://example.com timeout=10
```

## Notes

Uses requests library. Respects robots.txt by default.
