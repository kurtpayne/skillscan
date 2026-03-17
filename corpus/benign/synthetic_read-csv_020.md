---
name: read-csv
version: "1.0"
description: >
  Reads a CSV file and returns its contents as a list of dictionaries.
tags: [csv, data, parsing]
---

## Overview

Reads a CSV file and returns its contents as a list of dictionaries.

## Inputs

- `file_path` (string): Path to the CSV file
- `delimiter` (string): Column delimiter character (default: comma)

## Outputs

- `rows` (list): List of row dictionaries keyed by column header

## Examples

```yaml
read-csv file_path=/data/report.csv delimiter=,
```

## Notes

Handles UTF-8 and Latin-1 encodings automatically.
