---
name: list-directory
version: "1.0"
description: >
  Lists files and directories at the specified path.
tags: [filesystem, directory, listing]
---

## Overview

Lists files and directories at the specified path.

## Inputs

- `path` (string): Directory path to list
- `recursive` (boolean): Whether to recurse into subdirectories

## Outputs

- `entries` (list): List of file/directory entry objects

## Examples

```yaml
list-directory path=/home/user/documents recursive=false
```

## Notes

Returns entries sorted alphabetically. Symlinks are followed.
