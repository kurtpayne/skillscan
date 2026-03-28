# Pattern Updates

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
