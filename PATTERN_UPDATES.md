# Pattern Updates

## 2026-04-01

rulepack: 2026.04.01.1

Three new detection rules, IOC enrichment, and vuln DB updates.

- Added `MAL-057` (critical): **JarkaStealer AI package trojan** — Malicious PyPI packages `gptplus` (v2.2.0) and `claudeai-eng` (v1.0.0) masqueraded as AI model wrappers. The packages contained Base64-encoded payloads in `__init__.py` that downloaded `JavaUpdater.jar` from `github.com/imystorage/storage` to steal browser data, SSH keys, and credentials. Exfiltration to `api.github-analytics.com`.
- Added `EXEC-042` (high): **IDE config injection for silent command execution (CurXecute/MCPoison)** — CVE-2025-54135 (CurXecute) modifies global `mcp.json` via prompt injection through MCP-connected services like Slack. CVE-2025-54136 (MCPoison) exploits trust bypass where changes to an already-approved `mcp.json` are auto-trusted. Both enable arbitrary command execution in Cursor IDE without user interaction.
- Added `PINJ-018` (high): **Hidden prompt injection via CSS/HTML concealment** — Attackers use CSS properties (`display:none`, `font-size:0`, `opacity:0`) and HTML attributes (`aria-hidden`, HTML comments) to embed instructions invisible to humans but processed by AI agents. Observed in wild attacks against AI content moderation systems (December 2025).
- IOC update: added `api.github-analytics.com` (DevTools-Assistant MCP credential stealer C2) to domain IOC DB.
- Vuln DB update: added `gptplus` pip v2.2.0 as PYPI-GPTPLUS-2024-JARKASTEALER (critical, package removed from PyPI).
- Vuln DB update: added `claudeai-eng` pip v1.0.0 as PYPI-CLAUDEAIENG-2024-JARKASTEALER (critical, package removed from PyPI).
- Vuln DB update: added `devtools-assistant` pip v0.1.0 as PYPI-DEVTOOLS-ASSISTANT-2025-MCP (critical, package removed from PyPI).
- Vuln DB update: added `@anthropic-ai/mcp-inspector` npm v0.14.0 as CVE-2025-49596 (critical, fixed in 0.14.1).

Sources:
- Kaspersky Securelist: https://securelist.com/jarkastealer-supply-chain-attack/114937/
- Trail of Bits CurXecute: https://www.trailofbits.com/documents/CurXecute.pdf
- Trail of Bits MCPoison: https://www.trailofbits.com/documents/MCPoison.pdf
- Imperva: https://www.imperva.com/blog/ai-content-moderation-prompt-injection/
- GitHub Advisory CVE-2025-49596: https://github.com/advisories/GHSA-mcp-inspector-rce

## 2026-03-31 (patch 2)

rulepack: 2026.03.31.2

One new detection rule, IOC enrichment, and vuln DB update for the axios npm supply chain attack.

- Added `SUP-024` (critical): **Compromised axios npm versions (TeamPCP RAT dropper, March 2026)** — axios versions 1.14.1 and 0.30.4 were published to npm on March 30, 2026 via a hijacked maintainer account (jasonsaayman). The malicious versions inject a hidden dependency, `plain-crypto-js@4.2.1`, whose postinstall script drops a cross-platform RAT targeting macOS, Windows, and Linux. The RAT harvests SSH keys, cloud tokens, and credentials exfiltrating to `sfrclak.com:8000`. axios has ~100M weekly downloads; ~3% of affected environments showed confirmed execution. Linked to the ongoing TeamPCP supply chain campaign.
- IOC update: added `sfrclak.com` (axios RAT C2) to domain IOC DB.
- IOC update: added `142.11.206.73` (axios RAT C2 server IP) to IP IOC DB.
- Vuln DB update: added `axios` npm versions 1.14.1 and 0.30.4 as NPM-AXIOS-2026-03 (critical). Safe versions: 1.7.9+ (1.x) / 0.29.0+ (0.x).

Sources:
- The Hacker News (2026-03): https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html
- StepSecurity (2026-03-30): https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- Snyk (2026-03): https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
- Aikido Security (2026-03): https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
- Socket.dev (2026-03): https://socket.dev/blog/axios-npm-package-compromised

## 2026-03-31

rulepack: 2026.03.31.1

Three new detection rules, IOC enrichment, and vuln DB updates.

- Added `MAL-055` (critical): **postmark-mcp BCC email harvesting** — First confirmed malicious MCP server in production (npm publisher `phanpak`, versions 1.0.16–1.0.18). Injected a silent BCC on every outbound email to `phan@giftshop.club`, silently copying all AI-automated email content (password resets, invoices, internal memos) to the attacker. No existing rule covered MCP server BCC injection.
- Added `MAL-056` (critical): **Nx/s1ngularity AI CLI weaponization** — The s1ngularity campaign (August 2025) weaponized locally installed AI CLIs (claude, gemini, amazon q) with permission-bypass flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) via a malicious `telemetry.js` postinstall hook to enumerate and exfiltrate credentials. Destructive payload appended `sudo shutdown -h 0` to shell rc files. Exfil to `s1ngularity-repository-NNNN` GitHub repos.
- Added `SUP-023` (critical): **mcp-remote OAuth authorization_endpoint command injection (CVE-2025-6514)** — CVSS 9.6 critical. Affects mcp-remote npm 0.0.5–0.1.15 (437K+ downloads). A malicious MCP server returns a crafted `authorization_endpoint` (e.g., `a:$(cmd.exe /c whoami)?response_type=code`) that is passed unsanitized to the OS shell, enabling full RCE on the MCP client. Fixed in 0.1.16.
- IOC update: added `giftshop.club` (postmark-mcp BCC exfil), `trackpipe.dev` (openclaw-ai C2), `freefan.net` and `fanfree.net` (SANDWORM_MODE DNS exfil) to domain IOC DB.
- IOC update: added `83.142.209.203` (TeamPCP Telnyx C2) to IP IOC DB.
- Vuln DB update: added `mcp-remote` npm versions 0.0.5–0.1.15 as CVE-2025-6514 (critical, fixed 0.1.16).
- Vuln DB update: added `telnyx` Python versions 4.87.1 and 4.87.2 as PYPI-TELNYX-2026-03 (critical) — TeamPCP WAV steganography supply chain attack (March 27, 2026). C2 at 83.142.209.203:8080.

Sources:
- Snyk (2025-09): https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/
- The Hacker News (2025-09): https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html
- Snyk (2025-08): https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/
- InfoQ (2025-10): https://www.infoq.com/news/2025/10/npm-s1ngularity-shai-hulud/
- JFrog (2025): https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
- GitHub Advisory: https://github.com/advisories/GHSA-6xpm-ggf7-wc3p
- Datadog Security Labs (2026-03): https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- The Register (2026-03-30): https://www.theregister.com/2026/03/30/telnyx_pypi_supply_chain_attack_litellm/

## 2026-03-27 (patch 2)

rulepack: 2026.03.27.2

CI fix: three new chain rules, three new action patterns, metadata completion, test isolation fixes.

- Added `CHN-012` (critical): **Stealth concealment with network exfiltration chain** — co-occurrence of `stealth_concealment` + `network` action patterns. Detects skills that instruct the agent to hide its actions while also making outbound network calls.
- Added `CHN-013` (critical): **Container escape with host path mount chain** — co-occurrence of `docker_socket` + `privileged_container` action patterns. Detects privileged containers that also mount the Docker socket, enabling full host compromise.
- Added `CHN-014` (critical): **Container escape with secret access chain** — co-occurrence of `privileged_container` + `secret_access` action patterns. Detects privileged containers that also access credential files or environment variables.
- Added action patterns: `stealth_concealment`, `docker_socket`, `privileged_container`.
- Fixed incomplete metadata blocks on MAL-054, PINJ-016, EXF-020, ABU-002, SUP-001.
- Fixed showcase 78 to include SCP exfil trigger for CHN-011.
- Added `tests/conftest.py` lru_cache autouse fixture to prevent cross-test cache poisoning.
- Added `--debug` flag to `skillscan scan` CLI to surface which rule files are loaded at startup.

Sources:
- Internal CI failure analysis — see `docs/postmortem-2026-03-27-ci-failures.md`

## 2026-03-27

rulepack: 2026.03.27.1

Three new detection rules added for threats identified since the 2026-03-26 update.

- Added `MAL-054` (critical): **GlassWorm multi-stage Chrome extension RAT**. The GlassWorm campaign evolved to a multi-stage RAT that force-installs a malicious Chrome extension for keylogging and cookie theft, kills Ledger Live processes to show phishing windows, and exfiltrates data via Solana-based dead-drops. This is distinct from MAL-032 (persistence marker) and MAL-029 (Solana RPC C2 resolution).
- Added `PINJ-016` (high): **AI documentation context poisoning (ContextHub)**. Attackers poison community documentation portals (specifically contexthub.ai) with hidden instructions that trick AI coding agents into installing malicious packages. No existing rule covered this documentation-as-injection-vector attack.
- Added `EXF-020` (critical): **TeamPCP sysmon backdoor Kubernetes lateral movement**. The TeamPCP campaign (via LiteLLM) deploys a persistent C2 backdoor capable of laterally compromising every node in a Kubernetes cluster by enumerating secrets. MAL-049 covers the initial infection; this rule covers the Kubernetes secret enumeration and lateral movement pattern.
- IOC update: added `models.litellm.cloud` to domain IOC DB.
- Vuln DB update: added litellm 1.82.7 and 1.82.8 as compromised versions.

Sources:
- Aikido Security (2026-03): https://www.aikido.dev/blog/glassworm-chrome-extension-rat
- The Hacker News (2026-03): https://thehackernews.com/2026/03/glassworm-malware-uses-solana-dead.html
- The Register (2026-03-25): https://www.theregister.com/2026/03/25/ai_agents_supply_chain_attack_context_hub/
- StepSecurity (2026-03-24): https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel

## 2026-03-26

rulepack: 2026.03.26.1

- Added `MAL-050` (critical): **Ghost Campaign malicious npm packages (sudo phishing RAT)**.
- Added `MAL-051` (critical): **Embedded binary or shellcode (base64/hex-encoded executable)**.
- Added `MAL-052` (high): **Token/cost harvesting - skill instructs agent to loop or generate excessive output**.
- Added `MAL-053` (critical): **EICAR test string detected in skill file**.
- Added `SUP-021` (critical): **TeamPCP Checkmarx VS Code extension compromise (Open VSX)**.
- Added `SUP-022` (critical): **React Native npm account takeover supply chain attack**.
- Added `PINJ-015` (high): **Prompt poaching via malicious browser extension installation**.

## 2026-03-16

rulepack: 2026.03.16.1

- Added `EXF-016` (high): **Azure MCP resource-identifier URL substitution token-leak marker**.
