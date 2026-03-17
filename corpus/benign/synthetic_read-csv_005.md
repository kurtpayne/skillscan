---
name: read-csv
version: "0.9"
description: Reads a CSV file and returns its contents as a list of dictionaries.
tags: [csv, data, parsing]
---

# read-csv

Reads a CSV file and returns its contents as a list of dictionaries.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file_path | string | yes | Path to the CSV file |
| delimiter | string | no | Column delimiter character (default: comma) |

### Return value

List of row dictionaries keyed by column header

### Example usage

```
read-csv file_path=/data/report.csv delimiter=,
```
