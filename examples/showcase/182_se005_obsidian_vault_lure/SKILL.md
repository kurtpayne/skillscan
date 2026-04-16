# Obsidian Shared Vault Social Engineering Lure (REF6598 / PHANTOMPULSE)
This document describes the social engineering component of the REF6598 campaign
(Elastic Security Labs, April 14 2026) that delivers PHANTOMPULSE RAT via
Obsidian shared vault abuse.

## Attack Overview

Threat actors pose as venture capital firm representatives on LinkedIn, targeting
individuals in the financial and cryptocurrency sectors. After initial engagement,
the conversation moves to a Telegram group where multiple purported partners
participate, lending credibility to the interaction.

The target is asked to use Obsidian as the firm's "management database" for
accessing a shared dashboard. The target is provided credentials to connect to
a cloud-hosted vault controlled by the attacker.

## Social Engineering Lure

The attacker provides:
1. Obsidian account credentials (email + password) for the attacker-controlled vault
2. Instructions to enable community plugin sync in Obsidian settings
3. A plausible business context (cryptocurrency liquidity solutions)

Once the victim enables community plugin sync, the trojanized Shell Commands
plugin configuration (data.json) syncs automatically. On the next configured
trigger (vault open), the payload executes without further interaction.

## Key Indicators

- Unsolicited Obsidian vault credentials from LinkedIn/Telegram contacts
- Requests to enable "community plugin sync" for a shared vault
- VC firm personas on LinkedIn moving to Telegram
- References to cryptocurrency liquidity, financial services, or shared dashboards
- Obsidian vault described as a "management database" or "shared dashboard"

## Why This Works

The attack abuses legitimate Obsidian functionality rather than exploiting a
vulnerability. The payload lives entirely within JSON configuration files
(data.json) that are unlikely to trigger traditional AV signatures. Execution
is handed off by a signed, trusted Electron application, making parent-process-
based detection the critical detection layer.

## Mitigation

Never accept Obsidian vault credentials from unknown parties. Disable community
plugin sync for untrusted vaults. Monitor for anomalous child process creation
from Obsidian.exe (Windows) or Obsidian (macOS). Organizations in financial and
crypto sectors should train staff to recognize this lure pattern.

## References

- Elastic Security Labs: https://www.elastic.co/security-labs/phantom-in-the-vault
- The Hacker News: https://thehackernews.com/2026/04/obsidian-plugin-abuse-delivers.html
