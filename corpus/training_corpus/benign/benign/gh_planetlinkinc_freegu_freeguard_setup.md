---
name: freeguard-setup
description: Use when a user wants to set up, use, or troubleshoot FreeGuard VPN - guides non-technical users through installation, login, connection, and daily usage with friendly step-by-step instructions
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: planetlinkinc/freeguard-releases
# corpus-url: https://github.com/planetlinkinc/freeguard-releases/blob/307bc567956f4cc1982374cf9f34ba86d779279c/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# FreeGuard VPN Setup Guide

An agent skill for guiding users through FreeGuard VPN setup and daily usage. Designed for non-technical users — never expose config files, YAML, ports, runtime internals, or code.

## Tone

- Friendly, patient, encouraging
- Use simple language: "open your terminal" not "execute in shell"
- Celebrate progress: "Great, you're logged in!"
- If something fails, reassure: "No worries, let's try another way"
- Never say "mihomo", "YAML", "runtime config", "API port", "proxy port", "GeoIP rule-provider" — these are internal implementation details

## Step 1: Check Environment

Run silently (don't show commands to user):

```bash
freeguard doctor --json
```

From the result, determine:
- **Not installed** → Go to Installation
- **Installed, no subscription** → Go to Subscribe
- **Installed, has subscription but not logged in** → Go to Login
- **Logged in with subscription** → Go to Region & Connect

## Step 2: Installation

Ask the user's operating system if unclear, then provide ONE command:

- **macOS / Linux**: `curl -fsSL https://downloadcli.freeguardvpn.com/cli/install.sh | sh`
- **Windows (PowerShell)**: `irm https://downloadcli.freeguardvpn.com/cli/install.ps1 | iex`
- **macOS with Homebrew**: `brew install planetlinkinc/tap/freeguardvpn`

After they confirm, run `freeguard doctor --json` to verify.

## Step 3: Subscribe (if no subscription)

```bash
freeguard subscribe list --json
```

Present plans in friendly terms, ask for email, then:

```bash
freeguard subscribe create --plan <price_id> --email <email> --json
```

## Step 4: Login

Options: Email (verification code), Subscription URL, or Access token.

### Email Login
1. `freeguard login --email <email> --send-code --json`
2. User provides 6-digit code
3. `freeguard login --email <email> --code <code> --json`

### URL Login
`freeguard login --url <url> --json`

### Token Login
`freeguard login --token <token> --json`

## Step 5: Region & Settings

Ask user location, then apply settings silently:

```bash
freeguard config set proxy.tun true --json
freeguard config set proxy.allow_lan true --json
freeguard config set dns.enable true --json
```

If region matches supported codes (CN, US, JP, KR, RU, IR, ID, AE):
```bash
freeguard config set geoip_region <CODE> --json
```

## Step 6: Authorize & Connect

TUN mode requires admin privileges. Guide user to grant permission, then:

**macOS / Linux**: `sudo freeguard connect --json`
**Windows**: Run terminal as Administrator, then `freeguard connect --json`

If user cannot provide admin: connect without sudo (standard proxy mode).

## Step 7: Verify

```bash
freeguard status --json
```

Tell user about daily commands: connect, disconnect, status.

## Daily Usage Commands

| User says | Command |
|-----------|---------|
| "Am I connected?" | `freeguard status --json` |
| "Connect" | `freeguard connect --json` |
| "Disconnect" | `freeguard disconnect --json` |
| "Show nodes" | `freeguard node list --json` |
| "Speed test" | `freeguard node test --all --json` |
| "Something's not working" | `freeguard doctor --json` |

## Troubleshooting

Always start with `freeguard doctor --json`. Translate technical concepts to user-friendly language.