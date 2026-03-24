---
name: march7th
description: >
  运行 March7thAssistant (Honkai: Star Rail automation) on Windows.
  Use when: 清体力、跑差分宇宙/模拟宇宙、启动/关闭小助手、更新组件、检查环境。
  This skill is markdown-only and executes actions via terminal commands.
metadata:
  {
    "openclaw":
      {
        "emoji": "🌸",
        "os": ["win32"],
        "requires": { "bins": ["python", "git"] },
        "primaryEnv": null,
        "env": [],
      },
  }
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: rojim666/openclaw-skills-march7th
# corpus-url: https://github.com/rojim666/openclaw-skills-march7th/blob/6d264f8ce2f47c3bce8dfe4f14b1cf22615c0d43/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# March7thAssistant Skill Pack

Windows-only markdown workflow for running March7thAssistant.

## Source Repo

- Repo URL: `https://github.com/moesnow/March7thAssistant`
- Fallback path (if not found): `D:\Game\March7thAssistant_full\March7thAssistant_full`

## Step 1: Search Existing Source Folder

Run this first. It searches common roots for an existing repo folder.

```powershell
function Find-March7thRepo {
  param([string[]]$SearchRoots)

  foreach ($root in $SearchRoots) {
    if (-not (Test-Path $root)) { continue }

    $candidate = Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -like "*March7thAssistant*" } |
      Where-Object {
        (Test-Path (Join-Path $_.FullName "main.py")) -and
        (Test-Path (Join-Path $_.FullName "requirements.txt"))
      } |
      Select-Object -First 1

    if ($candidate) {
      return $candidate.FullName
    }
  }

  return $null
}

$searchRoots = @(
  "D:\\Game",
  "D:\\",
  "E:\\Game",
  "$env:USERPROFILE\\Downloads",
  "$env:USERPROFILE\\Desktop"
)

$repo = Find-March7thRepo -SearchRoots $searchRoots
if ($repo) {
  Write-Host "Found source repo: $repo"
} else {
  Write-Host "Source repo not found in searched paths."
}
```

If `$repo` is empty, run the bootstrap block below.

## Step 2: Clone To D Drive If Missing

```powershell
$fallbackRepo = "D:\\Game\\March7thAssistant_full\\March7thAssistant_full"

if (-not $repo) {
  $repoParent = Split-Path -Parent $fallbackRepo
  New-Item -ItemType Directory -Force -Path $repoParent | Out-Null

  if (-not (Test-Path $fallbackRepo)) {
    git clone --recurse-submodules https://github.com/moesnow/March7thAssistant $fallbackRepo
  }

  $repo = $fallbackRepo
}

Write-Host "Using repo: $repo"
```

## Step 3: Install Dependencies And Configure Environment

```powershell
$py = Join-Path $repo ".venv\\Scripts\\python.exe"

if (-not (Test-Path $py)) {
  python -m venv (Join-Path $repo ".venv")
}

& $py -m pip install -U pip
& $py -m pip install -r (Join-Path $repo "requirements.txt")

# Optional component updates (recommended once after install)
& $py (Join-Path $repo "main.py") universe_update
& $py (Join-Path $repo "main.py") fight_update

# First-time config GUI (manually set game_path)
& $py (Join-Path $repo "app.py") -S
```

## Commands

```powershell
$py = Join-Path $repo ".venv\\Scripts\\python.exe"

# Launch March7th launcher
Start-Process "$repo\March7th Launcher.exe"

# Run daily/full flow
$py "$repo\main.py" main

# Run universe flow
$py "$repo\main.py" universe

# Run universe GUI mode
$py "$repo\main.py" universe_gui

# Update modules
$py "$repo\main.py" universe_update
$py "$repo\main.py" fight_update

# Open config GUI
$py "$repo\app.py" -S

# Currency Wars
$py "$repo\app.py" currencywars -e

# Stop assistant only
taskkill /f /im March7th.exe 2>nul
taskkill /f /im "March7th Assistant.exe" 2>nul

# Stop assistant + game
taskkill /f /im March7th.exe 2>nul
taskkill /f /im "March7th Assistant.exe" 2>nul
taskkill /f /im StarRail.exe 2>nul
```

## Intent Mapping

- User says `打开小助手` -> `launch`
- User says `清体力` -> `run main` then optional delayed `stop --include-game`
- User says `跑差分宇宙` or `跑模拟宇宙` -> `run universe`
- User says `跑货币战争` -> `python app.py currencywars -e`
- User says `更新宇宙组件` -> `update universe`
- User says `关闭游戏` -> `stop --include-game`

## Troubleshooting

- `repo path not found`: run clone bootstrap section first.
- `Launcher not found`: check `March7th Launcher.exe` exists under repo path.
- `UAC` or permission issues: run elevated terminal.