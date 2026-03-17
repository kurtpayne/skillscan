---
name: validate-schema
version: "1.0"
description: >
  Validates a JSON document against a JSON Schema.
tags: [validation, schema, json]
---

## Overview

Validates a JSON document against a JSON Schema.

## Inputs

- `document` (dict): The JSON document to validate
- `schema` (dict): The JSON Schema to validate against

## Outputs

- `valid` (boolean): True if the document is valid

## Examples

```yaml
validate-schema document={...} schema={...}
```

## Notes

Returns detailed error messages on validation failure.
