---
name: calculate-hash
version: "1.0"
description: >
  Computes a cryptographic hash of a file or string.
tags: [security, hash, crypto]
---

## Overview

Computes a cryptographic hash of a file or string.

## Inputs

- `input` (string): File path or string to hash
- `algorithm` (string): Hash algorithm: sha256, sha512, md5

## Outputs

- `hash` (string): Hexadecimal hash digest

## Examples

```yaml
calculate-hash input=/path/to/file algorithm=sha256
```

## Notes

MD5 is provided for compatibility only; prefer SHA-256 or SHA-512.
