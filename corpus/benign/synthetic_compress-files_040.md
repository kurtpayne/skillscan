---
name: compress-files
version: "1.0"
description: >
  Compresses one or more files into a ZIP or tar.gz archive.
tags: [compression, archive, files]
---

## Overview

Compresses one or more files into a ZIP or tar.gz archive.

## Inputs

- `files` (list): List of file paths to compress
- `output_path` (string): Path for the output archive

## Outputs

- `archive_path` (string): Path to the created archive

## Examples

```yaml
compress-files files=[/tmp/a.txt, /tmp/b.txt] output_path=/tmp/archive.zip
```

## Notes

Supports ZIP and tar.gz formats based on output file extension.
