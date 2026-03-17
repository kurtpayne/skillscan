---
name: calculate-hash
version: "0.9"
description: Computes a cryptographic hash of a file or string.
tags: [security, hash, crypto]
---

# calculate-hash

Computes a cryptographic hash of a file or string.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| input | string | yes | File path or string to hash |
| algorithm | string | no | Hash algorithm: sha256, sha512, md5 |

### Return value

Hexadecimal hash digest

### Example usage

```
calculate-hash input=/path/to/file algorithm=sha256
```
