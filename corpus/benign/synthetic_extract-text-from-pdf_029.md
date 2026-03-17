---
name: extract-text-from-pdf
version: "0.9"
description: Extracts plain text content from a PDF file.
tags: [pdf, text, extraction]
---

# extract-text-from-pdf

Extracts plain text content from a PDF file.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file_path | string | yes | Path to the PDF file |
| pages | list | no | Optional list of page numbers to extract (1-indexed) |

### Return value

The extracted plain text

### Example usage

```
extract-text-from-pdf file_path=/docs/report.pdf pages=[1,2,3]
```
