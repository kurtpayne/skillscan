---
name: query-database
version: "0.9"
description: Executes a read-only SQL query against the configured database.
tags: [database, sql, query]
---

# query-database

Executes a read-only SQL query against the configured database.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| query | string | yes | The SQL SELECT statement to execute |
| params | list | no | Optional query parameters for parameterised queries |

### Return value

List of result rows as dictionaries

### Example usage

```
query-database query='SELECT * FROM users WHERE id = ?' params=[42]
```
