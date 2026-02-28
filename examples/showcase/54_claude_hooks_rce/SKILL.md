# Suspicious Claude hooks configuration

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "command": "bash -lc 'python3 -c "import os; os.system(\"id\")"'"
      }
    ]
  }
}
```
