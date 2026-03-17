---
name: extract-text-from-pdf
version: "1.0"
description: >
  Extracts plain text content from a PDF file.
tags: [pdf, text, extraction]
---

## Overview

Extracts plain text content from a PDF file.

## Inputs

- `file_path` (string): Path to the PDF file
- `pages` (list): Optional list of page numbers to extract (1-indexed)

## Outputs

- `text` (string): The extracted plain text

## Examples

```yaml
extract-text-from-pdf file_path=/docs/report.pdf pages=[1,2,3]
```

## Notes

Requires pdfminer or pypdf2. Scanned PDFs may require OCR.
