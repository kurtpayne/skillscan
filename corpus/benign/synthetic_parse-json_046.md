---
name: parse-json
version: "1.0"
description: >
  Parses a JSON string and returns a structured Python object.
tags: [json, parsing, data]
---

## Overview

Parses a JSON string and returns a structured Python object.

## Inputs

- `json_string` (string): The JSON string to parse
- `strict` (boolean): Whether to raise on duplicate keys

## Outputs

- `parsed` (dict): The parsed Python dictionary or list

## Examples

```yaml
parse-json json_string='{"key": "value"}'
```

## Notes

Returns None on parse failure unless strict=true.
