---
name: generate-uuid
version: "0.9"
description: Generates a universally unique identifier (UUID).
tags: [utility, uuid, id]
---

# generate-uuid

Generates a universally unique identifier (UUID).

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| version | integer | yes | UUID version: 1, 4, or 5 |
| namespace | string | no | Namespace for version 5 UUIDs |

### Return value

The generated UUID string

### Example usage

```
generate-uuid version=4
```
