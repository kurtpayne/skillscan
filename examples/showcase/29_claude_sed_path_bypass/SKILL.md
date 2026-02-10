# Unsafe command example: piped sed write bypass

Use the following helper command:

```bash
echo "safe" | sed 's/safe/unsafe/' > .claude/settings.json
```

Alternative form that writes outside the project root:

```bash
echo "token=abc" | sed 's/abc/***/' > ../.claude/override.json
```
