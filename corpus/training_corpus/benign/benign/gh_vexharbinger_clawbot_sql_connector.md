---
name: sql-connector
description: "Generic SQL Server connectivity for OpenClaw agents. Use when: (1) executing parameterized queries against SQL Server, (2) building repository layers that need a sealed, retry-capable SQL transport, (3) any agent that needs reliable MSSQL access without subprocess/sqlcmd. Provides execute/query/scalar APIs via pymssql with automatic retry, connection pooling, and structured error handling."
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: VeXHarbinger/clawbot-sql-connector
# corpus-url: https://github.com/VeXHarbinger/clawbot-sql-connector/blob/d6097a59e0fb6be3810bb5690d551e751b8d82ba/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# SQL Connector Skill
> Generic SQL Server connectivity for OpenClaw agents — pymssql transport

## Overview

Provides a reusable, sealed SQL Server connection layer with automatic retry, parameterized queries, and structured error handling. Built on **pymssql** (native TDS driver — no sqlcmd required).

## Installation

```bash
clawhub install sql-connector
```

## Quick Start

```python
from sql_connector import get_connector

db = get_connector('cloud')   # or 'local'

# Execute (INSERT/UPDATE/DELETE)
ok = db.execute("INSERT INTO memory.Logs (msg) VALUES (%s)", ("hello",))

# Query (SELECT → list of dicts)
rows = db.query("SELECT id, name FROM memory.Memories WHERE category=%s", ("facts",))

# Scalar (single value)
count = db.scalar("SELECT COUNT(*) FROM memory.TaskQueue WHERE status='pending'")
```

## Environment Variables

```
SQL_CLOUD_SERVER=sql5112.site4now.net
SQL_CLOUD_DATABASE=db_99ba1f_memory4oblio
SQL_CLOUD_USER=...
SQL_CLOUD_PASSWORD=...

SQL_LOCAL_SERVER=10.0.0.110
SQL_LOCAL_DATABASE=Oblio_Memories
SQL_LOCAL_USER=sa
SQL_LOCAL_PASSWORD=...
```

## Architecture

```
SQLConnector (ABC, _LockCoreMethods metaclass)
  execute() / query() / scalar()  ← SEALED — parameterized only, no override
  MSSQLConnector (pymssql, TDS 7.4)
    └── get_connector(backend) factory
```

`execute()` and `query()` are sealed by metaclass — subclasses cannot override them, enforcing parameterized-only access.

## License

MIT