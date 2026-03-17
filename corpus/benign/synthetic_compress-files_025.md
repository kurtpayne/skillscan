---
name: compress-files
version: "0.9"
description: Compresses one or more files into a ZIP or tar.gz archive.
tags: [compression, archive, files]
---

# compress-files

Compresses one or more files into a ZIP or tar.gz archive.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| files | list | yes | List of file paths to compress |
| output_path | string | no | Path for the output archive |

### Return value

Path to the created archive

### Example usage

```
compress-files files=[/tmp/a.txt, /tmp/b.txt] output_path=/tmp/archive.zip
```
