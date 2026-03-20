---
name: generate-uuid
version: "1.0"
description: >
  Generates a universally unique identifier (UUID).
tags: [utility, uuid, id]
---

## Overview

Generates a universally unique identifier (UUID).

## Inputs

- `version` (integer): UUID version: 1, 4, or 5
- `namespace` (string): Namespace for version 5 UUIDs

## Outputs

- `uuid` (string): The generated UUID string

## Examples

```yaml
generate-uuid version=4
```

## Notes

Version 4 is recommended for most use cases.
