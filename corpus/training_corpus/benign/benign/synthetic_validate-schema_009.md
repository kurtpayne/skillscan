---
name: validate-schema
version: "0.9"
description: Validates a JSON document against a JSON Schema.
tags: [validation, schema, json]
---

# validate-schema

Validates a JSON document against a JSON Schema.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| document | dict | yes | The JSON document to validate |
| schema | dict | no | The JSON Schema to validate against |

### Return value

True if the document is valid

### Example usage

```
validate-schema document={...} schema={...}
```
