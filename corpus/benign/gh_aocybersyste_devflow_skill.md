---
name: debug
version: "1.0"
description: Analyze logs across services, diagnose errors, and identify root causes
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: AO-Cyber-Systems/devflow
# corpus-url: https://github.com/AO-Cyber-Systems/devflow/blob/HEAD/skills/debug/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Debug and Log Analysis

Analyze logs across services to diagnose issues and identify root causes.

## Usage

- `/devflow-debug` - Analyze all services for recent errors
- `/devflow-debug api` - Focus on specific service logs
- `/devflow-debug --all` - Comprehensive log dump from all services
- `/devflow-debug "connection refused"` - Search for specific error message
- `/devflow-debug --since 1h` - Analyze logs from last hour

## Arguments

$ARGUMENTS

## Debugging Workflow

### Step 1: Identify the Scope

Determine what to investigate:
- Specific service name → focus on that service
- Error message in quotes → search across all services
- No arguments → scan all services for errors

### Step 2: Gather Service State

```bash
docker compose ps --format json
```

Identify:
- Which services are running/stopped/restarting
- Exit codes for stopped services
- Restart counts (indicates crash loops)

### Step 3: Collect Logs

**For specific service:**
```bash
devflow dev logs <service> --tail 200
```

**For all services:**
```bash
docker compose logs --tail 100 --timestamps
```

**Search for error patterns:**
```bash
docker compose logs --tail 500 2>&1 | grep -i "error\|exception\|fatal\|failed\|panic"
```

### Step 4: Analyze Error Patterns

Look for common issues:

**Connection Errors:**
- "connection refused" → target service not running or wrong port
- "connection reset" → service crashed during request
- "timeout" → service overloaded or network issue

**Database Errors:**
- "relation does not exist" → missing migration
- "permission denied" → wrong database user/role
- "too many connections" → connection pool exhausted

**Application Errors:**
- Stack traces → identify file and line number
- "undefined" / "null" → missing configuration or data
- "out of memory" → increase container memory limit

### Step 5: Check Dependencies

If service A fails, check its dependencies:

```bash
# Check database connectivity
docker compose exec <service> pg_isready -h postgres -p 5432

# Check Redis connectivity
docker compose exec <service> redis-cli -h redis ping

# Check external API connectivity
docker compose exec <service> curl -s https://api.example.com/health
```

### Step 6: Resource Analysis

Check if resource limits are causing issues:

```bash
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

Look for:
- Memory at 100% → OOM kills
- High CPU → infinite loop or heavy processing

### Step 7: Container Inspection

For crashed containers:

```bash
docker inspect <container_name> --format '{{.State.ExitCode}}'
docker inspect <container_name> --format '{{.State.Error}}'
```

Common exit codes:
- 0: Normal exit
- 1: Application error
- 137: OOM killed (128 + 9)
- 139: Segmentation fault (128 + 11)
- 143: SIGTERM (128 + 15)

## Output Format

```
DEBUG REPORT
============

Service: api
Status: running (restart count: 3)
Last restart: 5 minutes ago

RECENT ERRORS (last 50 lines)
-----------------------------
[2025-01-21 10:15:32] ERROR: Connection refused to postgres:5432
[2025-01-21 10:15:33] ERROR: Failed to initialize database pool
[2025-01-21 10:15:33] FATAL: Shutting down due to initialization failure

ROOT CAUSE ANALYSIS
-------------------
The API service cannot connect to PostgreSQL.

Possible causes:
1. PostgreSQL container not running
2. PostgreSQL still initializing
3. Network connectivity issue
4. Wrong connection string

DIAGNOSTIC CHECKS
-----------------
[FAIL] PostgreSQL container: not running
[OK]   Network: devflow-proxy exists
[OK]   Config: DATABASE_URL is set

RECOMMENDED FIX
---------------
Start the PostgreSQL container:

  docker compose up -d postgres

Then restart the API:

  docker compose restart api
```

## Interactive Debugging

For deeper investigation, suggest:

```bash
# Shell into container
devflow dev shell <service>

# Watch logs in real-time
devflow dev logs <service> --follow

# Check environment variables
docker compose exec <service> env | sort

# Test database connection manually
docker compose exec <service> psql $DATABASE_URL -c "SELECT 1"
```

## Common Fixes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Service restart loop | Missing dependency | Start dependencies first |
| Connection refused | Target not running | `docker compose up -d <target>` |
| OOM killed | Memory limit too low | Increase memory in compose |
| Permission denied | Wrong user/perms | Check volume permissions |
| Module not found | Missing build | `docker compose build <service>` |
| Port already in use | Conflicting service | Stop conflicting process |