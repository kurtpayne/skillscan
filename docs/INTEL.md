# Intel Guide

Intel sources are local files registered with SkillScan.

SkillScan also includes managed intel feeds that auto-refresh on scan by default.
Default refresh behavior:

1. Check managed intel age on every `scan`.
2. Refresh if older than 60 minutes.
3. Continue scanning even if refresh errors occur.

## Supported types

- `ioc`: JSON with `domains`, `ips`, `urls`
- `vuln`: JSON keyed by ecosystem/package/version
- `rules`: reserved for future rulepack expansions

## Example IOC file

```json
{
  "domains": ["bad.example"],
  "ips": ["203.0.113.10"],
  "urls": ["https://bad.example/loader.sh"]
}
```

## Commands

```bash
skillscan intel status
skillscan intel list
skillscan intel add ./my_iocs.json --type ioc --name team-iocs
skillscan intel sync
skillscan intel sync --force
skillscan intel disable team-iocs
skillscan intel enable team-iocs
skillscan intel remove team-iocs
skillscan intel rebuild
```

## Scan-time auto refresh controls

```bash
skillscan scan ./target --intel-max-age-minutes 60
skillscan scan ./target --no-auto-intel
```
