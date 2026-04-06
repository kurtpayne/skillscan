## 2026-04-06
rulepack: 2026.04.06.1
Two new detection rules, IOC enrichment, and vuln DB updates.
- Added `SUP-029` (critical): **Malicious Strapi npm packages (Redis RCE / Credential Harvesting)** — 36 malicious npm packages disguised as Strapi CMS plugins were discovered in April 2026. These packages use postinstall scripts to exploit Redis and PostgreSQL, deploy reverse shells, harvest credentials, and drop persistent implants.
- Added `PSV-009` (critical): **Langflow Agentic Assistant RCE Vulnerability (CVE-2026-33873)** — A remote code execution flaw in Langflow Agentic Assistant allows attackers to execute LLM-generated Python code server-side, potentially leading to system compromise.
- IOC update: added `prod-strapi` to domain IOC DB.
- Vuln DB update: added `langflow` python version 1.0.0 as CVE-2026-33873 (critical, fixed 1.0.1).
Sources:
- The Hacker News (Strapi): https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html
- GBHackers (Strapi): https://gbhackers.com/36-malicious-strapi-npm/
- SentinelOne (Langflow): https://www.sentinelone.com/vulnerability-database/cve-2026-33873/
## 2026-04-05
rulepack: 2026.04.05.1

Two new detection rules, IOC enrichment, and vuln DB updates.

- Added `MAL-061` (critical): **NomShub cursor-tunnel sandbox escape and persistence via shell builtins** — NomShub (disclosed April 3, 2026 by Straiker) is a critical vulnerability chain in Cursor AI code editor. A malicious repository embeds indirect prompt injection to trick Cursor's AI agent into running shell builtin chains (export/cd) that escape the workspace sandbox, overwrite `~/.zshenv` for persistence, and activate cursor-tunnel for persistent remote shell access via spawn/fs_write RPC methods. The cursor-tunnel binary can also be hijacked via GitHub device code OAuth flow. Fixed in Cursor 3.0.
- Added `SUP-028` (critical): **UNC1069 social engineering lure domain (teams.onlivemeet.com)** — `teams.onlivemeet.com` is a known-malicious domain operated by UNC1069 (Sapphire Sleet / North Korean APT). The domain impersonates Microsoft Teams to trick open-source npm/Node.js maintainers into joining fake video calls, during which a RAT is installed. The compromised maintainer accounts are then used to publish malicious npm packages (e.g., axios 1.14.1 and 0.30.4 in the March 2026 Axios supply chain attack).

- IOC update: added `teams.onlivemeet.com` and `onlivemeet.com` to domain IOC DB.
- Vuln DB update: added `cursor` npm version 2.x as NOMSHUB-2026-04 (critical, fixed 3.0.0).

Sources:
- Straiker (NomShub): https://www.straiker.ai/blog/nomshub-cursor-remote-tunneling-sandbox-breakout
- The Hacker News (UNC1069): https://thehackernews.com/2026/04/unc1069-social-engineering-of-axios.html
- Socket.dev (UNC1069): https://socket.dev/blog/attackers-hunting-high-impact-nodejs-maintainers
- Microsoft Security Blog (Axios/UNC1069): https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/

## 2026-04-04
rulepack: 2026.04.04.1

Two new detection rules, IOC enrichment, and vuln DB updates for the Telnyx PyPI compromise.

- Added `MAL-060` (critical): **Telnyx PyPI WAV Steganography Credential Stealer** — The telnyx PyPI package (versions 4.87.1 and 4.87.2) was compromised by TeamPCP. The malware uses WAV audio steganography to hide a second-stage binary that drops a persistent executable (msbuild.exe) on Windows or harvests credentials on Linux/macOS.
- Added `SUP-027` (critical): **Compromised Telnyx package version reference** — Detects references to the known-malicious telnyx versions 4.87.1 and 4.87.2.

- IOC update: added `83.142.209.203` and `83.142.209.0/24` to IP IOC DB.
- Vuln DB update: added `telnyx` python versions 4.87.1 and 4.87.2 as PYPI-TELNYX-2026-03 (critical, fixed 4.87.3).

Sources:
- SafeDep (Telnyx Compromise): https://safedep.io/malicious-telnyx-pypi-compromise
- StepSecurity (Telnyx Compromise): https://www.stepsecurity.io/blog/teampcp-plants-wav-steganography-credential-stealer-in-telnyx-pypi-package

## 2026-04-03
rulepack: 2026.04.03.1

Three new detection rules, IOC enrichment, and vuln DB updates.

- Added `MAL-059` (critical): **GlassWorm 5th Wave MCP Server Supply Chain Attack** — The GlassWorm campaign has entered its 5th wave, targeting MCP servers, GitHub repos, and VSCode extensions. It uses invisible Unicode characters to execute payloads. The first malicious MCP package identified is `@iflow-mcp/watercrawl-watercrawl-mcp`.
- Added `SUP-026` (critical): **MaliciousCorgi VS Code AI Extensions Data Exfiltration** — Two VS Code extensions (`whensunset.chatgpt-china` and `zhukunpeng.chat-moss`) with 1.5 million installs silently exfiltrate source code and developer profiles to Chinese servers (`aihao123.cn`).
- Added `PSV-008` (critical): **Cursor IDE CVE-2026-22708 RCE via Shell Built-ins** — A critical RCE vulnerability in Cursor IDE where implicitly trusted shell built-ins (`export`, `typeset`, `declare`) can be abused to manipulate environment variables and execute arbitrary code, bypassing the command allowlist.

- IOC update: added `aihao123.cn` to domain IOC DB.
- IOC update: added `45.32.150.251`, `45.32.151.157`, `70.34.242.255` to IP IOC DB.
- Vuln DB update: added `cursor` npm version 2.2.0 as CVE-2026-22708 (critical, fixed 2.3.0).
- Vuln DB update: added `@iflow-mcp/watercrawl-watercrawl-mcp` npm version 1.3.4 as NPM-GLASSWORM-2026-03 (critical).
- Vuln DB update: added `whensunset.chatgpt-china` npm version 1.0.0 as VSCODE-MALICIOUSCORGI-2026-01 (critical).

Sources:
- Koi Security (GlassWorm): https://www.koi.ai/blog/glassworm-hits-mcp-5th-wave-with-new-delivery-techniques
- Koi Security (MaliciousCorgi): https://www.koi.ai/blog/maliciouscorgi-the-cute-looking-ai-extensions-leaking-code-from-1-5-million-developers
- Pillar Security (Cursor RCE): https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors

# Pattern Updates
## 2026-04-02
rulepack: 2026.04.02.1

Three new detection rules, IOC enrichment, and vuln DB updates.

- Added `SUP-025` (critical): **ClawHub ranking manipulation vulnerability** — A vulnerability in ClawHub allowed attackers to artificially inflate download counts of malicious skills by exploiting an exposed internalMutation endpoint. This was used to push malicious skills to the #1 spot.
- Added `ABU-008` (high): **MCP tool description behavioral override (secretly/skip approval)** — MCP tool descriptions must not contain behavioral directives that instruct the LLM to act secretly, skip financial approvals, or hide actions from the user. These directives override security guardrails and can lead to unauthorized actions.
- Added `MAL-058` (critical): **Langflow CVE-2026-33017 unauthenticated RCE exploit** — CVE-2026-33017 is a critical unauthenticated remote code execution vulnerability in Langflow <= 1.8.2. Attackers can exploit the /api/v1/build_public_tmp/{flow_id}/flow endpoint by passing arbitrary Python code in the data parameter, which is executed via unsandboxed exec().

Sources:
- Silverfort: https://www.silverfort.com/blog/clawhub-vulnerability-enables-attackers-to-manipulate-rankings-to-become-the-number-one-skill/
- Cyber Security News: https://cybersecuritynews.com/clawhub-vulnerability-manipulate-rankings-to-become-the-1-skill/
- Reddit: https://www.reddit.com/r/cybersecurity/comments/1sanrxx/research_we_found_mcp_servers_telling_ai_agents/
- GitHub Advisory: https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33017

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
