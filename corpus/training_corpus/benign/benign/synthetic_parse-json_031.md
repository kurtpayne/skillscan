---
name: parse-json
version: "0.9"
description: Parses a JSON string and returns a structured Python object.
tags: [json, parsing, data]
---

# parse-json

Parses a JSON string and returns a structured Python object.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| json_string | string | yes | The JSON string to parse |
| strict | boolean | no | Whether to raise on duplicate keys |

### Return value

The parsed Python dictionary or list

### Example usage

```
parse-json json_string='{"key": "value"}'
```
