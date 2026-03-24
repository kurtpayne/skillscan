---
name: list-directory
version: "0.9"
description: Lists files and directories at the specified path.
tags: [filesystem, directory, listing]
---

# list-directory

Lists files and directories at the specified path.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | yes | Directory path to list |
| recursive | boolean | no | Whether to recurse into subdirectories |

### Return value

List of file/directory entry objects

### Example usage

```
list-directory path=/home/user/documents recursive=false
```
