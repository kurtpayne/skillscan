---
name: query-database
version: "1.0"
description: >
  Executes a read-only SQL query against the configured database.
tags: [database, sql, query]
---

## Overview

Executes a read-only SQL query against the configured database.

## Inputs

- `query` (string): The SQL SELECT statement to execute
- `params` (list): Optional query parameters for parameterised queries

## Outputs

- `rows` (list): List of result rows as dictionaries

## Examples

```yaml
query-database query='SELECT * FROM users WHERE id = ?' params=[42]
```

## Notes

Only SELECT statements are permitted. INSERT/UPDATE/DELETE will raise an error.
